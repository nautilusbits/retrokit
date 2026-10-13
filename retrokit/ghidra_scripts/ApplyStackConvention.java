// Sets parameter counts from the stack cleanup at call sites ("ADD ESP,n" right after
// the CALL). The caller removes exactly the bytes it pushed, so n/4 is the number of
// arguments - more reliable than what the decompiler infers from the callee's body,
// which misses parameters the callee never reads.
//
// Register convention (cspec "watcomreg", -3r/-5r): only functions called through the
// stack have such cleanups - varargs functions (sprintf, printf, ...) and libraries
// declared __cdecl (e.g. Miles AIL). They get __cdecl. Under the register default the
// decompiler would show them as f(junk EAX, junk EDX, junk EBX, junk ECX, real args...).
// Stack convention (cspec "watcom", -3s/-5s): every function is called that way; the
// calling convention is kept and only the parameter count is set.
//
// If all cleaned call sites agree on n the function gets n/4 int parameters and the tag
// STACK_ARGS (RecoverPrototypes then only commits the return type). If n differs between
// call sites the function is varargs: the fixed parameters end at the argument that is a
// format string ("...%...") at most call sites, else at min(n)/4; the signature gets
// "..." and is locked (the decompiler cannot see arguments reached only through va_list).
// Stack convention only: a function whose RETs all release the same n > 0 bytes ("RET n",
// e.g. the Watcom stack check __CHK called as "push size; call __CHK") pops its own
// arguments; it gets __stdcall with n/4 parameters and the tag. Left to the decompiler,
// such helpers get bogus parameter lists that then spread to every caller.
// Usage (headless): -preScript ApplyStackConvention.java [minRatio=0.5]
//@category RetroKit
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;

public class ApplyStackConvention extends GhidraScript {

	public static final String TAG = "STACK_ARGS";
	private static final int MAX_STRING = 256;

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		double minRatio = args.length > 0 ? Double.parseDouble(args[0]) : 0.5;
		String defaultCc = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
		boolean stackModel = defaultCc.contains("stack") || defaultCc.equals("__cdecl");
		String cc = stackModel ? defaultCc : "__cdecl";
		if (currentProgram.getFunctionManager().getCallingConvention(cc) == null) {
			printerr("Compiler spec has no " + cc + " prototype");
			return;
		}
		FunctionManager fm = currentProgram.getFunctionManager();
		int changed = 0, examined = 0, varargs = 0, byFormat = 0, calleePops = 0;
		for (Function f : fm.getFunctions(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			if (f.getTags().stream().anyMatch(t -> t.getName().equals("LIBRARY"))) {
				continue;   // documented prototype (ApplyLibraryPrototypes)
			}
			if (stackModel && fm.getCallingConvention("__stdcall") != null) {
				long popped = calleePop(f);
				if (popped > 0) {
					setParams(f, "__stdcall", (int) (popped / 4));
					f.addTag(TAG);
					calleePops++;
					changed++;
					continue;
				}
			}
			int calls = 0, cleaned = 0;
			long minPop = Long.MAX_VALUE, maxPop = 0;
			List<Instruction> cleanedCalls = new ArrayList<>();
			ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
			while (it.hasNext()) {
				Reference r = it.next();
				if (!r.getReferenceType().isCall()) {
					continue;
				}
				Instruction call = getInstructionAt(r.getFromAddress());
				if (call == null) {
					continue;
				}
				calls++;
				long n = cleanup(call);
				if (n > 0) {
					cleaned++;
					cleanedCalls.add(call);
					minPop = Math.min(minPop, n);
					maxPop = Math.max(maxPop, n);
				}
			}
			if (calls == 0) {
				continue;
			}
			examined++;
			if (cleaned == 0 || cleaned < minRatio * calls) {
				continue;
			}
			if (minPop != maxPop && cleaned >= 2) {
				int fixed = formatStringPosition(cleanedCalls, (int) (minPop / 4));
				if (fixed > 0) {
					byFormat++;
				}
				else {
					fixed = (int) (minPop / 4);
				}
				println(String.format("  varargs %s: %d fixed (%s), cleanup %d..%d bytes at %d of %d calls",
					f.getName(), fixed, byFormat > 0 && fixed != minPop / 4 ? "format string" : "min cleanup",
					minPop, maxPop, cleaned, calls));
				setParams(f, cc, fixed);
				f.setVarArgs(true);
				varargs++;
				changed++;
			}
			else if (minPop == maxPop) {
				setParams(f, cc, (int) (minPop / 4));
				f.addTag(TAG);
				changed++;
			}
		}
		println("ApplyStackConvention: " + changed + " functions with " + cc + " parameter counts from call-site " +
			"cleanup, " + varargs + " of them varargs (" + byFormat + " split at a format string), " + calleePops +
			" __stdcall from RET n (" + examined + " functions with call sites examined)");
	}

	private void setParams(Function f, String cc, int count) throws Exception {
		List<Parameter> params = new ArrayList<>();
		for (int i = 0; i < count; i++) {
			params.add(new ParameterImpl("param_" + (i + 1), Undefined4DataType.dataType, currentProgram));
		}
		f.updateFunction(cc, null, params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
			SourceType.ANALYSIS);
	}

	/** n if every RET of the function is "RET n" with the same n > 0, else 0. */
	private long calleePop(Function f) {
		long n = -1;
		for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
			if (!ins.getMnemonicString().equals("RET")) {
				continue;
			}
			long k = 0;
			if (ins.getNumOperands() == 1 && ins.getOpObjects(0).length == 1 &&
					ins.getOpObjects(0)[0] instanceof Scalar sc) {
				k = sc.getUnsignedValue();
			}
			if (n >= 0 && k != n) {
				return 0;
			}
			n = k;
		}
		return n > 0 && n < 0x100 && n % 4 == 0 ? n : 0;
	}

	/** n of an "ADD ESP,n" right after the call, else 0. */
	private long cleanup(Instruction call) {
		Instruction next = getInstructionAt(call.getMaxAddress().add(1));
		if (next == null || !next.getMnemonicString().equalsIgnoreCase("ADD") || next.getNumOperands() != 2) {
			return 0;
		}
		Object[] op0 = next.getOpObjects(0);
		Object[] op1 = next.getOpObjects(1);
		if (op0.length == 1 && op0[0].toString().equalsIgnoreCase("ESP") && op1.length == 1 &&
				op1[0] instanceof Scalar) {
			long n = ((Scalar) op1[0]).getUnsignedValue();
			if (n > 0 && n < 0x100 && n % 4 == 0 && pushesBefore(call) >= n / 4) {
				return n;
			}
		}
		return 0;
	}

	/**
	 * Argument words pushed for this call: PUSHes walking back from the call, minus the
	 * cleanup of nested calls in between (arguments computed by other calls), up to the
	 * frame allocation (SUB ESP), a RET/JMP or the function start. An "ADD ESP,n" after a
	 * call without n/4 such pushes releases the caller's own frame, not arguments.
	 */
	private int pushesBefore(Instruction call) {
		int pushes = 0, owed = 0; // owed: pushes further back that belong to a nested call
		Function f = getFunctionContaining(call.getAddress());
		Instruction ins = call.getPrevious();
		for (int back = 0; ins != null && back < 96; back++, ins = ins.getPrevious()) {
			if (f != null && !f.getBody().contains(ins.getAddress())) {
				break;
			}
			String m = ins.getMnemonicString();
			if (m.equals("RET") || m.equals("JMP")) {
				break;
			}
			if (m.equals("PUSH")) {
				if (owed > 0) {
					owed--;
				}
				else {
					pushes++;
				}
			}
			else if ((m.equals("ADD") || m.equals("SUB")) && ins.getNumOperands() == 2) {
				Object[] op0 = ins.getOpObjects(0);
				Object[] op1 = ins.getOpObjects(1);
				if (op0.length == 1 && op0[0].toString().equalsIgnoreCase("ESP") && op1.length == 1 &&
						op1[0] instanceof Scalar sc) {
					if (m.equals("SUB")) {
						break; // frame allocation
					}
					owed += (int) (sc.getUnsignedValue() / 4);
				}
			}
			if (ins.getAddress().equals(f == null ? null : f.getEntryPoint())) {
				break;
			}
		}
		return pushes;
	}

	/**
	 * 1-based position of the argument that is a format string at most of the given call
	 * sites (the last fixed parameter of a printf-like function), or 0.
	 */
	private int formatStringPosition(List<Instruction> calls, int maxArgs) {
		Map<Integer, Integer> votes = new HashMap<>();
		for (Instruction call : calls) {
			Instruction ins = call.getPrevious();
			int arg = 0;
			for (int back = 0; ins != null && back < 4 * maxArgs + 8 && arg < maxArgs; back++) {
				String m = ins.getMnemonicString();
				if (m.equals("CALL") || m.equals("RET") || m.startsWith("J")) {
					break;
				}
				if (m.equals("PUSH")) {
					arg++;
					if (isFormatString(pushedAddress(ins))) {
						votes.merge(arg, 1, Integer::sum);
						break;
					}
				}
				ins = ins.getPrevious();
			}
		}
		int best = 0, bestVotes = 0;
		for (Map.Entry<Integer, Integer> e : votes.entrySet()) {
			if (e.getValue() > bestVotes) {
				best = e.getKey();
				bestVotes = e.getValue();
			}
		}
		return bestVotes * 2 >= calls.size() ? best : 0;
	}

	/** Address a PUSH puts on the stack: its own reference, or the one loaded into the pushed register. */
	private Address pushedAddress(Instruction push) {
		for (Reference r : push.getReferencesFrom()) {
			if (r.getReferenceType().isData()) {
				return r.getToAddress();
			}
		}
		Object[] op = push.getOpObjects(0);
		if (op.length != 1 || !(op[0] instanceof ghidra.program.model.lang.Register)) {
			return null;
		}
		String reg = op[0].toString();
		Instruction ins = push.getPrevious();
		for (int back = 0; ins != null && back < 6; back++, ins = ins.getPrevious()) {
			Object[] dst = ins.getNumOperands() > 0 ? ins.getOpObjects(0) : new Object[0];
			if (dst.length == 1 && dst[0].toString().equals(reg)) {
				for (Reference r : ins.getReferencesFrom()) {
					if (r.getReferenceType().isData()) {
						return r.getToAddress();
					}
				}
				return null; // register loaded with something else
			}
		}
		return null;
	}

	private boolean isFormatString(Address a) {
		if (a == null) {
			return false;
		}
		Data d = getDataAt(a);
		String s = null;
		if (d != null && d.hasStringValue()) {
			s = String.valueOf(d.getValue());
		}
		else {
			try {
				byte[] b = getBytes(a, MAX_STRING);
				int n = 0;
				while (n < b.length && b[n] != 0) {
					if (b[n] < 7 || (b[n] & 0xff) > 126) {
						return false;
					}
					n++;
				}
				s = n < b.length ? new String(b, 0, n, "ISO-8859-1") : null;
			}
			catch (Exception e) {
				return false;
			}
		}
		return s != null && s.matches("(?s).*%[-+ #0-9.]*[diouxXscpfeEgGl].*");
	}
}

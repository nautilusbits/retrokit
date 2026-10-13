// Programs built with the Watcom register convention (-3r/-5r, cspec "watcomreg") still
// call some functions through the stack: varargs functions (sprintf, printf, ...) and
// libraries declared __cdecl (e.g. Miles AIL). Their callers push every argument and
// clean up with "ADD ESP,n" right after the CALL. Under the register default the
// decompiler shows them as f(junk EAX, junk EDX, junk EBX, junk ECX, real args...).
//
// This script sets __cdecl on every function whose direct call sites are mostly
// followed by ADD ESP,imm. If the cleanup size differs between call sites the function
// is varargs: it gets min(n)/4 fixed int parameters + "..." and a locked signature
// (RecoverPrototypes skips varargs functions; the decompiler cannot see arguments that
// are only reached through va_list and would commit too few). Fixed-parameter counts
// are an upper bound: if every call passes at least one variadic argument it is counted
// as fixed.
// Usage (headless): -preScript ApplyStackConvention.java [minRatio=0.5]
//@category RetroKit
import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.Undefined4DataType;
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

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		double minRatio = args.length > 0 ? Double.parseDouble(args[0]) : 0.5;
		String cc = "__cdecl";
		if (currentProgram.getFunctionManager().getCallingConvention(cc) == null) {
			printerr("Compiler spec has no " + cc + " prototype");
			return;
		}
		FunctionManager fm = currentProgram.getFunctionManager();
		int changed = 0, examined = 0, varargs = 0;
		for (Function f : fm.getFunctions(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			int calls = 0, cleaned = 0;
			long minPop = Long.MAX_VALUE, maxPop = 0;
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
				Instruction next = getInstructionAt(call.getMaxAddress().add(1));
				if (next != null && next.getMnemonicString().equalsIgnoreCase("ADD")
						&& next.getNumOperands() == 2) {
					Object[] op0 = next.getOpObjects(0);
					Object[] op1 = next.getOpObjects(1);
					if (op0.length == 1 && op0[0].toString().equalsIgnoreCase("ESP")
							&& op1.length == 1 && op1[0] instanceof Scalar) {
						long n = ((Scalar) op1[0]).getUnsignedValue();
						if (n > 0 && n < 0x100 && n % 4 == 0) {
							cleaned++;
							minPop = Math.min(minPop, n);
							maxPop = Math.max(maxPop, n);
						}
					}
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
				// varargs: fixed int params from the smallest cleanup, then "..."
				List<Parameter> params = new ArrayList<>();
				for (int i = 0; i < minPop / 4; i++) {
					params.add(new ParameterImpl("param_" + (i + 1), Undefined4DataType.dataType,
						currentProgram));
				}
				f.updateFunction(cc, null, params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
					SourceType.ANALYSIS);
				f.setVarArgs(true);
				varargs++;
				changed++;
			}
			else if (!cc.equals(f.getCallingConventionName())) {
				// only the model: a non-DEFAULT signature source would lock the (still empty)
				// parameter list and the decompiler would never show the stack arguments
				f.setCallingConvention(cc);
				changed++;
			}
		}
		println("ApplyStackConvention: " + changed + " functions set to " + cc + ", " + varargs +
			" of them varargs (" + examined + " functions with call sites examined)");
	}
}

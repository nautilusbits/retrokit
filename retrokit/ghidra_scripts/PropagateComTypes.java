// Types the variables that hold COM interface pointers (DirectX and others declared in
// retrokit/knowledge/win32), so calls through their vtables decompile as
// (*g_dd->lpVtbl->CreateSurface)(g_dd,...) instead of (**(code **)(*g_dd + 0x18))(...).
//
// Starts at the calls of functions whose prototype has an out-parameter "Interface **"
// (DirectDrawCreate, DirectSoundCreate, ...; typed by ApplyLibraryPrototypes) or returns an
// interface pointer (Direct3DCreate9): the global or local variable whose address is passed
// (or that receives the result) gets the type "Interface *". Then the functions using those
// variables are decompiled again, where calls through the now typed vtables have prototypes
// with further out-parameters (CreateSurface -> IDirectDrawSurface **, GetAttachedSurface,
// CreateSoundBuffer, CreateDevice, ...), until nothing changes. An interface is a structure
// whose first field is "lpVtbl".
//   -postScript PropagateComTypes.java [rounds=6]
//@category RetroKit
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

public class PropagateComTypes extends GhidraScript {

	private DecompInterface ifc;
	private int globals, locals, overrideCount;
	private final Set<Address> overridden = new HashSet<>();
	private final List<Object[]> overrides = new ArrayList<>();

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int rounds = args.length > 0 ? Integer.parseInt(args[0]) : 6;
		int methods = stdcallMethods();
		Set<Function> work = new LinkedHashSet<>();
		int seeds = 0;
		for (Function ext : currentProgram.getFunctionManager().getExternalFunctions()) {
			if (producesInterface(ext.getSignature())) {
				seeds++;
				work.addAll(callers(ext.getEntryPoint()));
			}
		}
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			if (!f.isThunk() && producesInterface(f.getSignature())) {
				work.addAll(callers(f.getEntryPoint()));
			}
		}
		if (work.isEmpty()) {
			println("PropagateComTypes: no calls of functions that create interfaces (" + seeds + " such imports)");
			return;
		}
		ifc = new DecompInterface();
		ifc.setOptions(new DecompileOptions());
		ifc.toggleCCode(false);
		ifc.openProgram(currentProgram);
		int round = 0, decompiled = 0;
		try {
			while (!work.isEmpty() && round++ < rounds && !monitor.isCancelled()) {
				Set<Function> next = new LinkedHashSet<>();
				for (Function f : work) {
					DecompileResults res = ifc.decompileFunction(f, 30, monitor);
					decompiled++;
					HighFunction hf = res == null ? null : res.getHighFunction();
					if (hf != null) {
						next.addAll(process(f, hf));
					}
				}
				work = next;
			}
		}
		finally {
			ifc.dispose();
		}
		println(String.format("PropagateComTypes: %d globals and %d locals typed as interface pointers, " +
			"%d vtable calls with their prototype (%d rounds, %d functions decompiled, %d vtable methods set to " +
			"__stdcall)", globals, locals, overrideCount, round, decompiled, methods));
	}

	/** COM methods are __stdcall, but Ghidra's C parser drops the calling convention of
	 *  function pointers inside structures: put it back on every *Vtbl member */
	private int stdcallMethods() throws Exception {
		int n = 0;
		Iterator<Structure> it = currentProgram.getDataTypeManager().getAllStructures();
		List<Structure> vtbls = new ArrayList<>();
		while (it.hasNext()) {
			Structure s = it.next();
			if (s.getName().endsWith("Vtbl")) {
				vtbls.add(s);
			}
		}
		for (Structure s : vtbls) {
			for (DataTypeComponent c : s.getComponents()) {
				if (c.getDataType() instanceof Pointer p && p.getDataType() instanceof FunctionDefinition fd &&
					!"__stdcall".equals(fd.getCallingConventionName())) {
					fd.setCallingConvention("__stdcall");
					n++;
				}
			}
		}
		return n;
	}

	/** functions to look at again after this one's variables were typed */
	private Set<Function> process(Function f, HighFunction hf) throws Exception {
		Set<Function> again = new LinkedHashSet<>();
		Iterator<PcodeOpAST> it = hf.getPcodeOps();
		List<Object[]> todo = new ArrayList<>();      // collected first: typing invalidates hf
		while (it.hasNext()) {
			PcodeOpAST op = it.next();
			if (op.getOpcode() != PcodeOp.CALL && op.getOpcode() != PcodeOp.CALLIND) {
				continue;
			}
			FunctionSignature sig = signatureOf(op);
			if (sig == null) {
				continue;
			}
			if (op.getOpcode() == PcodeOp.CALLIND && sig instanceof FunctionDefinition fd &&
				fd.getArguments().length > 0 && interfaceOf(fd.getArguments()[0].getDataType(), 1) != null) {
				// a call through a typed vtable: the decompiler decides how much the callee pops
				// before it uses types, so tell it with a call-site override (__stdcall, n args)
				Address site = op.getSeqnum().getTarget();
				if (overridden.add(site)) {
					overrides.add(new Object[] { site, fd });
				}
			}
			ParameterDefinition[] params = sig.getArguments();
			for (int i = 0; i < params.length && i + 1 < op.getNumInputs(); i++) {
				Structure iface = interfaceOf(params[i].getDataType(), 2);
				if (iface != null) {
					todo.add(new Object[] { op.getInput(i + 1), iface, Boolean.TRUE });
				}
			}
			Structure ret = interfaceOf(sig.getReturnType(), 1);
			if (ret != null && op.getOutput() != null) {
				todo.add(new Object[] { op.getOutput(), ret, Boolean.FALSE });
			}
		}
		boolean localChanged = false;
		for (Object[] o : overrides) {
			HighFunctionDBUtil.writeOverride(f, (Address) o[0], (FunctionDefinition) o[1]);
			overrideCount++;
			localChanged = true;
		}
		overrides.clear();
		for (Object[] t : todo) {
			Varnode v = (Varnode) t[0];
			Structure iface = (Structure) t[1];
			boolean byAddress = (Boolean) t[2];
			DataType ptr = new PointerDataType(iface, currentProgram.getDataTypeManager());
			if (byAddress) {
				Address g = globalAddress(v);
				if (g != null) {
					if (typeGlobal(g, ptr)) {
						again.addAll(users(g));
					}
					continue;
				}
				HighSymbol s = stackSymbol(v, hf);
				if (s != null && setLocal(s, ptr)) {
					localChanged = true;
				}
			}
			else {
				HighVariable hv = v.getHigh();
				HighSymbol s = hv == null ? null : hv.getSymbol();
				if (s == null) {
					continue;
				}
				if (s.isGlobal() && s.getStorage().isMemoryStorage()) {
					Address g = s.getStorage().getMinAddress();
					if (typeGlobal(g, ptr)) {
						again.addAll(users(g));
					}
				}
				else if (setLocal(s, ptr)) {
					localChanged = true;
				}
			}
		}
		if (localChanged) {
			again.add(f);
		}
		return again;
	}

	private boolean setLocal(HighSymbol s, DataType ptr) throws Exception {
		if (s.getDataType() != null && s.getDataType().isEquivalent(ptr)) {
			return false;
		}
		HighFunctionDBUtil.updateDBVariable(s, null, ptr, SourceType.USER_DEFINED);
		locals++;
		return true;
	}

	private boolean typeGlobal(Address g, DataType ptr) throws Exception {
		Data d = getDataAt(g);
		if (d != null && d.getDataType().isEquivalent(ptr)) {
			return false;
		}
		DataUtilities.createData(currentProgram, g, ptr, -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		globals++;
		return true;
	}

	/** prototype of the called function: a direct callee (thunks followed), the external
	 *  function an import slot points to, or the function-pointer type of a vtable entry */
	private FunctionSignature signatureOf(PcodeOp op) {
		Varnode t = op.getInput(0);
		if (op.getOpcode() == PcodeOp.CALL) {
			Function callee = getFunctionAt(t.getAddress());
			if (callee == null) {
				return null;
			}
			Function real = callee.isThunk() ? callee.getThunkedFunction(true) : callee;
			return real.getSignature();
		}
		HighVariable hv = t.getHigh();
		if (hv != null && hv.getDataType() instanceof Pointer p && p.getDataType() instanceof FunctionDefinition fd) {
			return fd;
		}
		PcodeOp def = t.getDef();
		if (def != null && def.getOpcode() == PcodeOp.LOAD && def.getInput(1).isConstant()) {
			Address slot = toAddr(def.getInput(1).getOffset());
			for (Reference r : getReferencesFrom(slot)) {
				Function f = getFunctionAt(r.getToAddress());
				if (f != null) {
					return f.getSignature();
				}
			}
		}
		return null;
	}

	/** the interface structure behind "Interface *" (depth 1) or "Interface **" (depth 2) */
	private static Structure interfaceOf(DataType t, int depth) {
		for (int i = 0; i < depth; i++) {
			t = strip(t);
			if (!(t instanceof Pointer p)) {
				return null;
			}
			t = p.getDataType();
		}
		t = strip(t);
		if (t instanceof Structure s && s.getNumComponents() >= 1) {
			DataTypeComponent c = s.getComponent(0);
			if ("lpVtbl".equals(c.getFieldName())) {
				return s;
			}
		}
		return null;
	}

	private static DataType strip(DataType t) {
		while (t instanceof TypeDef td) {
			t = td.getBaseDataType();
		}
		return t;
	}

	private static boolean producesInterface(FunctionSignature sig) {
		if (sig == null) {
			return false;
		}
		if (interfaceOf(sig.getReturnType(), 1) != null) {
			return true;
		}
		for (ParameterDefinition p : sig.getArguments()) {
			if (interfaceOf(p.getDataType(), 2) != null) {
				return true;
			}
		}
		return false;
	}

	/** the global whose address the varnode is, or null */
	private Address globalAddress(Varnode v) {
		for (int depth = 0; v != null && depth < 4; depth++) {
			if (v.isConstant()) {
				Address a = toAddr(v.getOffset());
				return currentProgram.getMemory().contains(a) ? a : null;
			}
			PcodeOp def = v.getDef();
			if (def == null) {
				return null;
			}
			switch (def.getOpcode()) {
				case PcodeOp.COPY:
				case PcodeOp.CAST:
					v = def.getInput(0);
					break;
				case PcodeOp.PTRSUB:
					if (def.getInput(0).isConstant() && def.getInput(0).getOffset() == 0) {
						v = def.getInput(1);
						break;
					}
					return null;
				default:
					return null;
			}
		}
		return null;
	}

	/** the stack variable whose address the varnode is (PTRSUB of the stack pointer), or null */
	private HighSymbol stackSymbol(Varnode v, HighFunction hf) {
		PcodeOp def = v.getDef();
		while (def != null && (def.getOpcode() == PcodeOp.COPY || def.getOpcode() == PcodeOp.CAST)) {
			def = def.getInput(0).getDef();
		}
		if (def == null || def.getOpcode() != PcodeOp.PTRSUB || !def.getInput(1).isConstant()) {
			return null;
		}
		Varnode base = def.getInput(0);
		if (!base.isRegister() && !(base.getHigh() != null && base.getHigh().getName().contains("stack"))) {
			// the decompiler's stack base is a register varnode (ESP at entry)
			if (!base.isInput()) {
				return null;
			}
		}
		long off = def.getInput(1).getOffset();
		int stackOff = (int) off;
		Iterator<HighSymbol> syms = hf.getLocalSymbolMap().getSymbols();
		while (syms.hasNext()) {
			HighSymbol s = syms.next();
			if (s.getStorage().isStackStorage() && s.getStorage().getStackOffset() == stackOff) {
				return s;
			}
		}
		return null;
	}

	/** functions that reference the address (code reading a global) */
	private Set<Function> users(Address a) {
		Set<Function> out = new LinkedHashSet<>();
		for (Reference r : getReferencesTo(a)) {
			Function f = getFunctionContaining(r.getFromAddress());
			if (f != null) {
				out.add(f);
			}
		}
		return out;
	}

	/** functions calling the function at entry - directly, through thunks or import slots */
	private Set<Function> callers(Address entry) {
		Set<Function> out = new LinkedHashSet<>();
		Deque<Address> todo = new ArrayDeque<>(List.of(entry));
		Set<Address> seen = new HashSet<>();
		while (!todo.isEmpty()) {
			Address a = todo.pop();
			if (!seen.add(a) || seen.size() > 64) {
				continue;
			}
			for (Reference r : getReferencesTo(a)) {
				Address from = r.getFromAddress();
				Function f = getFunctionContaining(from);
				if (f != null && !f.isThunk()) {
					out.add(f);
				}
				else if (f != null) {
					todo.push(f.getEntryPoint());
				}
				else {
					todo.push(from);          // an import slot: who reads it
				}
			}
		}
		return out;
	}
}

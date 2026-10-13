// Recovers function prototypes (parameters + return) with the decompiler, the
// way "Decompiler Parameter ID" does, but in parallel, with a short per-function
// timeout and progress logging.
//
// Functions are processed bottom-up over the call graph: leaves first, then every
// function whose callees all have a committed prototype, and so on (cycles are cut
// at back edges). A caller is therefore decompiled only after its callees know
// their real parameter lists, so call sites do not pick up preserved registers
// (EBX/ECX/EDX under the Watcom register convention) as fake arguments, and the
// caller's own committed prototype does not inherit them.
// A committed (ANALYSIS) prototype stays locked, so one iteration is normally enough.
// A "void" return is never committed: the decompiler often cannot see EAX set on every path
// (results of tail calls), and a committed void turns every use at a call site into extraout_EAX.
//
// Trailing register parameters the decompiler named "unaff_<REG>" are dropped before the
// prototype is kept, unless at least half of the direct call sites load that register
// within the few instructions before the CALL. unaff_ parameters are usually callee-saved
// registers whose restore the decompiler could not prove on every path; committing them
// would make every caller pass its own preserved registers along. Caller evidence keeps
// the real ones, e.g. main(argc = EAX, argv = EDX) called after "mov edx,[argv]".
// (Checking data flow inside the callee instead does not work: partial register writes
// such as "mov bh,cl" make every saved register look used.)
//   -postScript RecoverPrototypes.java [iterations=1] [timeoutSec=20]
//@category RetroKit
import java.util.*;

import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.parallel.DecompilerCallback;
import ghidra.app.decompiler.parallel.ParallelDecompiler;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

public class RecoverPrototypes extends GhidraScript {

	private static final int LOOKBACK = 8;

	private static boolean stackArgs(Function f) {
		return f.getTags().stream().anyMatch(t -> t.getName().equals("STACK_ARGS"));
	}

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		int iterations = args.length > 0 ? Integer.parseInt(args[0]) : 1;
		int timeout = args.length > 1 ? Integer.parseInt(args[1]) : 20;

		List<Function> funcs = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			// varargs signatures come from ApplyStackConvention (call-site cleanup sizes)
			if (!f.isThunk() && !f.isExternal() && !f.hasVarArgs() && f.getBody().getNumAddresses() < 20000) {
				funcs.add(f);
			}
		}
		Map<Address, Set<String>> argRegs = callerLoadedRegisters(funcs);
		boolean regConv = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName()
			.equals("__watcall");
		List<List<Function>> levels = bottomUpLevels(funcs);
		println("Recovering prototypes for " + funcs.size() + " functions in " + levels.size() +
			" call-graph levels, " + iterations + " iteration(s)");

		for (int iter = 1; iter <= iterations; iter++) {
			final int it = iter;
			final int[] counts = new int[5]; // ok, failed, changed, unaff dropped, unaff kept
			for (int lvl = 0; lvl < levels.size() && !monitor.isCancelled(); lvl++) {
				DecompilerCallback<Boolean> cb = new DecompilerCallback<>(currentProgram, ifc -> {
					DecompileOptions opts = new DecompileOptions();
					ifc.setOptions(opts);
					ifc.toggleCCode(false);
					ifc.toggleSyntaxTree(true);
					ifc.setSimplificationStyle("decompile");
				}) {
					@Override
					public Boolean process(DecompileResults results, TaskMonitor m) {
						if (results == null || !results.decompileCompleted()) {
							synchronized (counts) { counts[1]++; }
							return false;
						}
						HighFunction hf = results.getHighFunction();
						if (hf == null) {
							synchronized (counts) { counts[1]++; }
							return false;
						}
						Function f = hf.getFunction();
						Set<String> loaded = argRegs.getOrDefault(f.getEntryPoint(), Collections.emptySet());
						Set<String> unsaved = regConv ? unsavedArgRegisters(f) : Collections.emptySet();
						String before = f.getSignature().getPrototypeString();
						try {
							synchronized (currentProgram) {
								if (stackArgs(f)) {
									// parameter count from call-site cleanup (ApplyStackConvention)
									if (!(hf.getFunctionPrototype().getReturnType() instanceof VoidDataType)) {
										f.setReturnType(hf.getFunctionPrototype().getReturnType(), SourceType.ANALYSIS);
									}
									synchronized (counts) { counts[0]++; }
									return true;
								}
								HighFunctionDBUtil.commitParamsToDatabase(hf, true,
									ReturnCommitOption.COMMIT_NO_VOID, SourceType.ANALYSIS);
								// an untyped 8-byte return is EDX left set by the callee, not a long long result
								if (f.getReturnType() instanceof Undefined8DataType) {
									f.setReturnType(DataType.DEFAULT, SourceType.DEFAULT);
								}
								Parameter[] ps = f.getParameters();
								int keep = ps.length;
								while (keep > 0 && ps[keep - 1].getName().startsWith("unaff_")) {
									Register r = ps[keep - 1].getRegister();
									String rn = r == null ? null : r.getBaseRegister().getName();
									if (rn != null && (loaded.contains(rn) || unsaved.contains(rn))) {
										counts[4]++;
										break;
									}
									keep--;
								}
								for (int i = ps.length - 1; i >= keep; i--) {
									f.removeParameter(i);
								}
								// kept register arguments are real parameters: drop the "unaff_" look
								for (int i = 0; i < keep; i++) {
									if (ps[i].getName().startsWith("unaff_")) {
										ps[i].setName("param_" + (i + 1), SourceType.ANALYSIS);
									}
								}
								counts[3] += ps.length - keep;
							}
						}
						catch (Exception e) {
							synchronized (counts) { counts[1]++; }
							return false;
						}
						String after = f.getSignature().getPrototypeString();
						synchronized (counts) {
							counts[0]++;
							if (!before.equals(after)) {
								counts[2]++;
							}
						}
						return true;
					}
				};
				cb.setTimeout(timeout);
				ParallelDecompiler.decompileFunctions(cb, levels.get(lvl), monitor);
				cb.dispose();
				if ((lvl + 1) % 10 == 0 || lvl + 1 == levels.size()) {
					println(String.format("iter %d level %d/%d: %d ok, %d failed, %d changed, unaff params %d dropped / %d kept",
						it, lvl + 1, levels.size(), counts[0], counts[1], counts[2], counts[3], counts[4]));
				}
			}
			println(String.format("iteration %d finished: %d ok, %d failed, %d signatures changed, unaff params %d dropped / %d kept",
				iter, counts[0], counts[1], counts[2], counts[3], counts[4]));
		}
	}

	/**
	 * For every function: base registers that at least half of its direct call sites write
	 * within LOOKBACK instructions before the CALL (stopping at CALL/RET/JMP).
	 */
	/**
	 * Register convention: argument registers (EDX, EBX, ECX) the function does not save in
	 * its prologue. A Watcom callee saves every register it modifies except EAX and the ones
	 * carrying arguments, so a register it reads without saving is an argument - evidence
	 * that also works for functions only called through pointer tables.
	 */
	private Set<String> unsavedArgRegisters(Function f) {
		Set<String> regs = new HashSet<>(Arrays.asList("EDX", "EBX", "ECX"));
		Instruction ins = getInstructionAt(f.getEntryPoint());
		for (int i = 0; i < 8 && ins != null && ins.getMnemonicString().equalsIgnoreCase("PUSH"); i++) {
			for (Object o : ins.getOpObjects(0)) {
				if (o instanceof Register reg && reg.getBaseRegister() != null) {
					regs.remove(reg.getBaseRegister().getName());
				}
			}
			ins = ins.getNext();
		}
		return regs;
	}

	private Map<Address, Set<String>> callerLoadedRegisters(List<Function> funcs) {
		Map<Address, Set<String>> out = new HashMap<>();
		for (Function f : funcs) {
			Map<String, Integer> hits = new HashMap<>();
			int calls = 0;
			ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
			while (refs.hasNext()) {
				Reference ref = refs.next();
				if (!ref.getReferenceType().isCall()) {
					continue;
				}
				Instruction call = getInstructionAt(ref.getFromAddress());
				if (call == null) {
					continue;
				}
				calls++;
				Set<String> written = new HashSet<>();
				Instruction ins = getInstructionBefore(call.getAddress());
				for (int i = 0; i < LOOKBACK && ins != null; i++) {
					if (ins.getFlowType().isCall() || ins.getFlowType().isTerminal() ||
						ins.getFlowType().isJump()) {
						break;
					}
					if (!ins.getMnemonicString().equalsIgnoreCase("PUSH")) {
						for (Object o : ins.getResultObjects()) {
							if (o instanceof Register reg && reg.getBaseRegister() != null) {
								written.add(reg.getBaseRegister().getName());
							}
						}
					}
					ins = getInstructionBefore(ins.getAddress());
				}
				for (String w : written) {
					hits.merge(w, 1, Integer::sum);
				}
			}
			Set<String> regs = new HashSet<>();
			for (Map.Entry<String, Integer> e : hits.entrySet()) {
				if (calls > 0 && e.getValue() * 2 >= calls) {
					regs.add(e.getKey());
				}
			}
			out.put(f.getEntryPoint(), regs);
		}
		return out;
	}

	/** Level 0 = functions without callees in the set; level n = max(callee level) + 1. Back edges ignored. */
	private List<List<Function>> bottomUpLevels(List<Function> funcs) throws Exception {
		Map<Address, Function> byEntry = new HashMap<>();
		for (Function f : funcs) {
			byEntry.put(f.getEntryPoint(), f);
		}
		Map<Address, List<Address>> callees = new HashMap<>();
		for (Function f : funcs) {
			List<Address> cs = new ArrayList<>();
			for (Function c : f.getCalledFunctions(monitor)) {
				if (byEntry.containsKey(c.getEntryPoint()) && !c.getEntryPoint().equals(f.getEntryPoint())) {
					cs.add(c.getEntryPoint());
				}
			}
			callees.put(f.getEntryPoint(), cs);
		}
		Map<Address, Integer> level = new HashMap<>();
		Set<Address> onStack = new HashSet<>();
		for (Function f : funcs) {
			// iterative DFS (deep call chains would overflow a recursive one)
			Address root = f.getEntryPoint();
			if (level.containsKey(root)) {
				continue;
			}
			Deque<Address> stack = new ArrayDeque<>();
			Deque<Iterator<Address>> iters = new ArrayDeque<>();
			stack.push(root);
			iters.push(callees.get(root).iterator());
			onStack.add(root);
			while (!stack.isEmpty()) {
				Iterator<Address> itr = iters.peek();
				if (itr.hasNext()) {
					Address c = itr.next();
					if (!level.containsKey(c) && !onStack.contains(c)) {
						stack.push(c);
						iters.push(callees.get(c).iterator());
						onStack.add(c);
					}
				}
				else {
					Address a = stack.pop();
					iters.pop();
					onStack.remove(a);
					int lv = 0;
					for (Address c : callees.get(a)) {
						Integer cl = level.get(c);
						if (cl != null) {
							lv = Math.max(lv, cl + 1);
						}
					}
					level.put(a, lv);
				}
			}
		}
		List<List<Function>> out = new ArrayList<>();
		for (Function f : funcs) {
			int lv = level.get(f.getEntryPoint());
			while (out.size() <= lv) {
				out.add(new ArrayList<>());
			}
			out.get(lv).add(f);
		}
		return out;
	}
}

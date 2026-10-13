// After clearing a bogus no-return flag, callers are still truncated: the
// bytes after each CALL were never disassembled and the function bodies end
// there. Disassemble the fall-through of every call site and recreate the
// bodies of the containing functions.
// Usage: -preScript FixTruncatedCallers.java [addr ...]
// With no arguments it processes every function currently flagged no-return
// that has a RET instruction in its body (the usual false positives).
//@category RetroKit
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;

public class FixTruncatedCallers extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// stop the analyzer from re-flagging these functions on the next pass
		setAnalysisOption(currentProgram, "Non-Returning Functions - Discovered", "false");
		Set<Function> toRecreate = new HashSet<>();
		int disassembled = 0;
		List<Address> targets = new ArrayList<>();
		for (String arg : getScriptArgs()) {
			targets.add(toAddr(Long.parseLong(arg, 16)));
		}
		if (targets.isEmpty()) {
			// auto mode: no-return functions that actually contain a RET
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (!f.hasNoReturn() || f.isExternal()) {
					continue;
				}
				for (Instruction ins : currentProgram.getListing().getInstructions(f.getBody(), true)) {
					if (ins.getFlowType().isTerminal() && ins.getMnemonicString().startsWith("RET")) {
						targets.add(f.getEntryPoint());
						break;
					}
				}
			}
			println("auto mode: " + targets.size() + " suspicious no-return functions");
		}
		for (Address target : targets) {
			Function tf = getFunctionAt(target);
			if (tf != null && tf.hasNoReturn()) {
				tf.setNoReturn(false);
				println("cleared noreturn on " + tf.getName());
			}
			for (Reference ref : getReferencesTo(target)) {
				if (!ref.getReferenceType().isCall()) {
					continue;
				}
				Instruction call = getInstructionAt(ref.getFromAddress());
				if (call == null) {
					continue;
				}
				// the no-return analyzer turned the CALL into a terminator: undo that
				if (call.getFlowOverride() != FlowOverride.NONE) {
					call.setFlowOverride(FlowOverride.NONE);
				}
				if (call.getFallThrough() == null) {
					call.clearFallThroughOverride();
				}
				Address next = call.getAddress().add(call.getLength());
				if (getInstructionAt(next) == null) {
					if (new DisassembleCommand(next, null, true).applyTo(currentProgram, monitor)) {
						disassembled++;
					}
				}
				Function caller = getFunctionContaining(call.getAddress());
				if (caller != null) {
					toRecreate.add(caller);
				}
			}
		}
		int fixed = 0;
		for (Function f : toRecreate) {
			long before = f.getBody().getNumAddresses();
			Address entry = f.getEntryPoint();
			CreateFunctionCmd cmd = new CreateFunctionCmd(entry, true);
			boolean ok = cmd.applyTo(currentProgram, monitor);
			Function nf = getFunctionAt(entry);
			long after = nf == null ? -1 : nf.getBody().getNumAddresses();
			if (after != before) {
				fixed++;
			}
			if (!ok) {
				println("recreate failed for " + f.getName() + ": " + cmd.getStatusMsg());
			}
		}
		println(String.format("disassembled %d fall-throughs, %d callers, %d bodies changed",
			disassembled, toRecreate.size(), fixed));
	}
}

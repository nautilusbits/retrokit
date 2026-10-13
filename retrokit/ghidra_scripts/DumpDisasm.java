// Prints the disassembly of a function (by entry address) to stdout.
// Usage: -postScript DumpDisasm.java 00012345 [more addrs]
//@category RetroKit
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class DumpDisasm extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (String a : getScriptArgs()) {
			Address addr = toAddr(Long.parseLong(a, 16));
			Function f = getFunctionContaining(addr);
			if (f == null) {
				println("no function at " + a);
				continue;
			}
			println("==== " + f.getName() + " " + f.getSignature().getPrototypeString() + " cc=" + f.getCallingConventionName());
			InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
			while (it.hasNext()) {
				Instruction ins = it.next();
				println(ins.getAddress() + "  " + ins.toString());
			}
		}
	}
}

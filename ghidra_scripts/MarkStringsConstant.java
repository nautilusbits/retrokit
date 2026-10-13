// DOS/4GW programs keep string literals in the writable data object. With correct block
// permissions (the LE loader now applies the object flags) the decompiler prints
// references to them as &DAT_xxx / s_label instead of "text", because anything in
// writable memory may change. This script marks every defined string (and char array
// holding a string) as mutability=constant, so the decompiler shows literals again while
// the rest of the data object stays writable (no bogus constant folding of globals).
// Caveat: a string buffer that the program rewrites at runtime is also shown as its
// initial literal wherever it is referenced.
// Usage (headless): -preScript MarkStringsConstant.java
//@category RetroKit
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryBlock;

public class MarkStringsConstant extends GhidraScript {

	@Override
	protected void run() throws Exception {
		int marked = 0, skipped = 0;
		for (Data d : currentProgram.getListing().getDefinedData(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			if (!d.hasStringValue()) {
				continue;
			}
			MemoryBlock b = currentProgram.getMemory().getBlock(d.getAddress());
			if (b == null || !b.isWrite()) {
				skipped++; // already read-only: literals are shown anyway
				continue;
			}
			if (MutabilitySettingsDefinition.DEF.getChoice(d) != MutabilitySettingsDefinition.CONSTANT) {
				MutabilitySettingsDefinition.DEF.setChoice(d, MutabilitySettingsDefinition.CONSTANT);
				marked++;
			}
		}
		println("MarkStringsConstant: " + marked + " strings marked constant (" + skipped +
			" in read-only blocks left alone)");
	}
}

// DOS/4GW programs keep string literals in the writable data object. With correct block
// permissions (the LE loader now applies the object flags) the decompiler prints
// references to them as &DAT_xxx / s_label instead of "text", because anything in
// writable memory may change. This script marks every defined string (and char array
// holding a string) as mutability=constant, so the decompiler shows literals again while
// the rest of the data object stays writable (no bogus constant folding of globals).
// Caveat: a string buffer that the program rewrites at runtime is also shown as its
// initial literal wherever it is referenced.
//
// Before that it defines the short strings Ghidra's ASCII analyzer leaves out (it needs
// 5 characters; "seed", "rb", "%d" are common): every address that code takes as a
// constant (push offset / mov reg, offset - not a memory read or write) in a non-code
// block, where no data is defined yet, holding at least MIN_LEN printable characters
// and a NUL.
// Usage (headless): -preScript MarkStringsConstant.java
//@category RetroKit
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.MutabilitySettingsDefinition;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class MarkStringsConstant extends GhidraScript {

	private static final int MIN_LEN = 2;
	private static final int MAX_LEN = 1024;

	@Override
	protected void run() throws Exception {
		int created = createShortStrings();
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
		println("MarkStringsConstant: " + created + " short strings defined, " + marked +
			" strings marked constant (" + skipped + " in read-only blocks left alone)");
	}

	private int createShortStrings() {
		int created = 0;
		for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			for (Reference r : ins.getReferencesFrom()) {
				RefType t = r.getReferenceType();
				if (!t.isData() || t.isRead() || t.isWrite()) {
					continue; // only addresses used as constants
				}
				Address a = r.getToAddress();
				MemoryBlock b = currentProgram.getMemory().getBlock(a);
				if (b == null || b.isExecute() || !b.isInitialized()) {
					continue;
				}
				Data d = getDataContaining(a);
				if (d != null && d.isDefined()) {
					continue;
				}
				int n = stringLength(a);
				if (n < MIN_LEN) {
					continue;
				}
				try {
					createAsciiString(a);
					created++;
				}
				catch (Exception e) {
					// overlaps other data
				}
			}
		}
		return created;
	}

	/** Printable characters before a NUL at a, or -1 if the bytes are not a C string. */
	private int stringLength(Address a) {
		for (int n = 0; n < MAX_LEN; n++) {
			int c;
			try {
				c = getByte(a.add(n)) & 0xff;
			}
			catch (Exception e) {
				return -1;
			}
			if (c == 0) {
				return n;
			}
			if (getDataContaining(a.add(n)) != null && getDataContaining(a.add(n)).isDefined()) {
				return -1; // runs into defined data
			}
			if (!(c >= 0x20 && c < 0x7f) && c != '\n' && c != '\r' && c != '\t') {
				return -1;
			}
		}
		return -1;
	}
}

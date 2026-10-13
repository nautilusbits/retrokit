// Creates functions at explicit entry points the auto-analysis missed.
//
// Usage (headless, as a -preScript so the re-analysis follows the new bodies):
//   -preScript CreateFunctionsAtEntries.java 127400 139caa ...     hex addresses
//   -preScript CreateFunctionsAtEntries.java @entries.txt           one hex address per line (# comments)
//   -preScript CreateFunctionsAtEntries.java --fixup-insns          see below
//   -preScript CreateFunctionsAtEntries.java --fixup-code=116600-166380   see below
//   -preScript CreateFunctionsAtEntries.java --gap-prologues=116600-166380 see below
//
// --fixup-insns: every applied 32-bit LE offset fixup (type 7) whose target is
// an already-disassembled instruction that no function contains becomes a
// function start, in ANY object. CreateFunctionsFromFixups only looks at
// .object1; some Watcom builds put the game code in .object2 (flags without
// the execute bit), so its pointer tables (AI state handlers, action handlers)
// were skipped. Only targets that are already instructions are taken, so data
// pointers into mixed code/data objects are left alone.
//
// --fixup-code=LO-HI: every applied type-7 fixup whose target lies in the code
// range [LO,HI) and whose SOURCE lies outside it (a pointer stored in data,
// i.e. a handler table entry) is disassembled and made a function start when
// no function contains it yet. Use it when the code shares an object with
// data and you know where the code part starts and ends.
//
// --gap-prologues=LO-HI: code nothing references directly (reached only via a
// register call or from not-yet-found code). In every undefined byte run in
// [LO,HI), skip the padding (00, 90, Watcom's 87 DB = xchg ebx,ebx) and, if
// the first real byte is a PUSH reg (50-57, the Watcom prologue), disassemble
// there and create a function. Repeats until a pass finds nothing new.
// Run it AFTER the fixup modes (arguments are processed in order).
//@category RetroKit
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.SourceType;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Iterator;

public class CreateFunctionsAtEntries extends GhidraScript {

	private int processed, created, disassembled, inside, failed;

	@Override
	protected void run() throws Exception {
		AddressSet targets = new AddressSet();
		for (String a : getScriptArgs()) {
			if (a.equals("--fixup-insns")) {
				targets.add(fixupTargets(null, null));
			}
			else if (a.startsWith("--gap-prologues=")) {
				String[] r = a.substring(16).split("-");
				for (Address t : targets.getAddresses(true)) {
					create(t);
				}
				targets.clear();
				gapPrologues(parse(r[0]), parse(r[1]));
			}
			else if (a.startsWith("--fixup-code=")) {
				String[] r = a.substring(13).split("-");
				targets.add(fixupTargets(parse(r[0]), parse(r[1])));
			}
			else if (a.startsWith("@")) {
				for (String line : Files.readAllLines(Paths.get(a.substring(1)))) {
					line = line.replaceAll("#.*", "").trim();
					if (!line.isEmpty()) {
						targets.add(parse(line));
					}
				}
			}
			else {
				targets.add(parse(a));
			}
		}
		for (Address t : targets.getAddresses(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			create(t);
		}
		println(String.format("Entries: %d processed, %d created (%d newly disassembled), %d inside an existing body, %d failed",
			processed, created, disassembled, inside, failed));
	}

	private Address parse(String s) {
		s = s.trim().toLowerCase();
		if (s.startsWith("0x")) {
			s = s.substring(2);
		}
		if (s.startsWith("fun_")) {
			s = s.substring(4);
		}
		return toAddr(Long.parseLong(s, 16));
	}

	private void create(Address t) throws Exception {
		processed++;
		Function f = getFunctionContaining(t);
		if (f != null) {
			if (!f.getEntryPoint().equals(t)) {
				inside++;
				println("inside " + f.getName() + ": " + t);
			}
			return;
		}
		if (getInstructionAt(t) == null) {
			if (getDataAt(t) != null && getDataAt(t).isDefined()) {
				clearListing(t);
			}
			DisassembleCommand dc = new DisassembleCommand(t, null, true);
			if (!dc.applyTo(currentProgram, monitor) || getInstructionAt(t) == null) {
				failed++;
				println("cannot disassemble " + t);
				return;
			}
			disassembled++;
		}
		CreateFunctionCmd fc = new CreateFunctionCmd(null, t, null, SourceType.ANALYSIS);
		if (fc.applyTo(currentProgram, monitor)) {
			created++;
		}
		else {
			failed++;
			println("cannot create function at " + t + ": " + fc.getStatusMsg());
		}
	}

	private void gapPrologues(Address lo, Address hi) throws Exception {
		AddressSet range = new AddressSet(lo, hi.subtract(1));
		int total = 0;
		for (int pass = 0; pass < 50 && !monitor.isCancelled(); pass++) {
			int before = created;
			ghidra.program.model.address.AddressSetView undef = currentProgram.getListing().getUndefinedRanges(range, false, monitor);
			for (ghidra.program.model.address.AddressRange r : undef.getAddressRanges()) {
				Address a = r.getMinAddress();
				Address end = r.getMaxAddress();
				while (a.compareTo(end) <= 0) {
					int b = getByte(a) & 0xff;
					if (b == 0x00 || b == 0x90) {
						a = a.add(1);
					}
					else if (b == 0x87 && a.compareTo(end) < 0 && (getByte(a.add(1)) & 0xff) == 0xdb) {
						a = a.add(2);
					}
					else {
						break;
					}
				}
				if (a.compareTo(end) > 0) {
					continue;
				}
				int b = getByte(a) & 0xff;
				if (b >= 0x50 && b <= 0x57 && getFunctionContaining(a) == null) {
					create(a);
				}
			}
			total += created - before;
			if (created == before) {
				break;
			}
		}
		println("Gap prologues in " + lo + "-" + hi + ": " + total + " functions");
	}

	/** lo == null: instruction targets in any object; else data-stored pointers into [lo,hi). */
	private AddressSet fixupTargets(Address lo, Address hi) throws Exception {
		AddressSet out = new AddressSet();
		Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
		while (it.hasNext() && !monitor.isCancelled()) {
			Relocation r = it.next();
			if (r.getType() != 7 || r.getStatus() != Relocation.Status.APPLIED) {
				continue;
			}
			Address src = r.getAddress();
			if (!currentProgram.getMemory().contains(src)) {
				continue;
			}
			long value;
			try {
				value = currentProgram.getMemory().getInt(src) & 0xffffffffL;
			}
			catch (Exception e) {
				continue;
			}
			Address t;
			try {
				t = src.getNewAddress(value);
			}
			catch (Exception e) {
				continue;
			}
			MemoryBlock b = currentProgram.getMemory().getBlock(t);
			if (b == null || !b.getName().startsWith(".object")) {
				continue;
			}
			if (getFunctionContaining(t) != null) {
				continue;
			}
			if (lo != null) {
				boolean srcInCode = src.compareTo(lo) >= 0 && src.compareTo(hi) < 0;
				if (srcInCode || t.compareTo(lo) < 0 || t.compareTo(hi) >= 0) {
					continue;
				}
				out.add(t);
				continue;
			}
			Instruction ins = getInstructionAt(t);
			if (ins == null) {
				continue;
			}
			// the fixup must not be the instruction's own operand pointing at itself
			if (ins.contains(src)) {
				continue;
			}
			out.add(t);
		}
		println((lo == null ? "Fixup targets that are instructions without a function: "
			: "Data-stored fixup targets in " + lo + "-" + hi + " without a function: ") + out.getNumAddresses());
		return out;
	}
}

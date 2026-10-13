// Watcom flat-model games reach most of their code through function-pointer
// tables in the data object (state machines, draw routines, ...). Every such
// pointer is an LE 32-bit offset fixup whose target lies in the code object,
// so walk the relocation table and create functions at those targets.
// Also follows fixups inside the code object itself (e.g. immediate operands
// of "mov eax, offset func").
//@category RetroKit
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.SourceType;

import java.util.Iterator;

public class CreateFunctionsFromFixups extends GhidraScript {

	@Override
	protected void run() throws Exception {
		MemoryBlock code = currentProgram.getMemory().getBlock(".object1");
		if (code == null) {
			printerr("No .object1 block");
			return;
		}
		Address codeStart = code.getStart();
		Address codeEnd = code.getEnd();

		int created = 0, disassembled = 0, skipped = 0, candidates = 0;
		Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
		AddressSet targets = new AddressSet();
		while (it.hasNext() && !monitor.isCancelled()) {
			Relocation r = it.next();
			// LE fixup type 7 = 32-bit offset (see LinearFixupRecord.SOURCE_32BIT_OFFSET_FIXUP)
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
			Address target = codeStart.getNewAddress(value);
			if (target.compareTo(codeStart) < 0 || target.compareTo(codeEnd) > 0) {
				continue;
			}
			// A pointer stored inside the code object that sits in the middle of an
			// instruction is an immediate operand; the disassembler already handled
			// its reference, but the target may still lack a function.
			if (currentProgram.getFunctionManager().getFunctionAt(target) != null) {
				continue;
			}
			if (currentProgram.getFunctionManager().getFunctionContaining(target) != null) {
				skipped++; // points into the body of a known function: not a function start
				continue;
			}
			targets.add(target);
		}
		candidates = (int) targets.getNumAddresses();
		println("Fixup targets without a function: " + candidates);

		for (Address target : targets.getAddresses(true)) {
			if (monitor.isCancelled()) {
				break;
			}
			Instruction ins = getInstructionAt(target);
			if (ins == null) {
				if (getDataAt(target) != null) {
					continue; // typed data lives here, leave it alone
				}
				DisassembleCommand dc = new DisassembleCommand(target, null, true);
				if (!dc.applyTo(currentProgram, monitor)) {
					continue;
				}
				disassembled++;
				ins = getInstructionAt(target);
				if (ins == null) {
					continue;
				}
			}
			CreateFunctionCmd fc = new CreateFunctionCmd(null, target, null, SourceType.ANALYSIS);
			if (fc.applyTo(currentProgram, monitor)) {
				created++;
			}
		}
		println(String.format("Created %d functions (%d newly disassembled), %d pointers into existing bodies",
			created, disassembled, skipped));
	}
}

// Watcom flat-model games reach most of their code through function-pointer
// tables in the data object (state machines, draw routines, ...). Every such
// pointer is an LE 32-bit offset fixup whose target lies in the code object,
// so walk the relocation table and create functions at those targets.
// Also follows fixups inside the code object itself (e.g. immediate operands
// of "mov eax, offset func").
//
// Watcom puts switch jump tables into the code object as well. A table is
// recognised by the fixup in the operand of an indirect "JMP [reg*4+table]";
// its entries become pointers, the case targets become computed-jump
// destinations of that JMP (so they stay inside the switch's function) and are
// never turned into functions. Functions created at case targets by an older
// run are removed again.
//@category RetroKit
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class CreateFunctionsFromFixups extends GhidraScript {

	/** Case code of a switch lies close to its JMP; a slot pointing further away ends the table. */
	private static final long MAX_CASE_DISTANCE = 0x4000;

	private Address codeStart, codeEnd;

	private boolean inCode(Address a) {
		return a.compareTo(codeStart) >= 0 && a.compareTo(codeEnd) <= 0;
	}

	@Override
	protected void run() throws Exception {
		MemoryBlock code = currentProgram.getMemory().getBlock(".object1");
		if (code == null) {
			printerr("No .object1 block");
			return;
		}
		codeStart = code.getStart();
		codeEnd = code.getEnd();

		// source -> target of every applied 32-bit offset fixup that points into code
		Map<Address, Address> fixups = new TreeMap<>();
		Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
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
			try {
				Address target = codeStart.getNewAddress(currentProgram.getMemory().getInt(src) & 0xffffffffL);
				if (inCode(target)) {
					fixups.put(src, target);
				}
			}
			catch (Exception e) {
				// unreadable source
			}
		}

		AddressSet caseEntries = new AddressSet();   // table slots
		AddressSet caseTargets = new AddressSet();
		int switches = splitSwitchTables(fixups, caseEntries, caseTargets);

		int created = 0, disassembled = 0, skipped = 0;
		AddressSet targets = new AddressSet();
		for (Map.Entry<Address, Address> e : fixups.entrySet()) {
			Address src = e.getKey(), target = e.getValue();
			if (caseEntries.contains(src) || caseTargets.contains(target)) {
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
		println("Fixup targets without a function: " + targets.getNumAddresses());

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
		// functions created above may contain switches whose JMP was not disassembled before
		switches += splitSwitchTables(fixups, caseEntries, caseTargets);
		println(String.format("Created %d functions (%d newly disassembled), %d pointers into existing bodies, " +
			"%d switch tables (%d cases)", created, disassembled, skipped, switches, caseTargets.getNumAddresses()));
	}

	/** Finds jump tables of indirect JMPs, wires their cases to the JMP; returns the number of tables. */
	private int splitSwitchTables(Map<Address, Address> fixups, AddressSet caseEntries, AddressSet caseTargets)
			throws Exception {
		List<Function> touched = new ArrayList<>();
		int tables = 0, removed = 0;
		for (Map.Entry<Address, Address> e : new ArrayList<>(fixups.entrySet())) {
			Instruction jmp = getInstructionContaining(e.getKey());
			if (jmp == null || !jmp.getMnemonicString().equals("JMP") || !jmp.getFlowType().isComputed()) {
				continue;
			}
			Address table = e.getValue();
			List<Address> cases = new ArrayList<>();
			for (Address slot = table; fixups.containsKey(slot) && !caseEntries.contains(slot);
					slot = slot.add(4)) {
				Address target = fixups.get(slot);
				if (Math.abs(target.subtract(jmp.getAddress())) > MAX_CASE_DISTANCE) {
					break; // too far from the JMP: the table ended, this is some other pointer
				}
				cases.add(target);
				caseEntries.add(slot, slot.add(3));
			}
			if (cases.isEmpty()) {
				continue;
			}
			tables++;
			Address tableEnd = table.add(4L * cases.size() - 1);
			clearListing(table, tableEnd);
			for (int i = 0; i < cases.size(); i++) {
				createData(table.add(4L * i), PointerDataType.dataType);
			}
			for (Address target : cases) {
				caseTargets.add(target);
				Function wrong = getFunctionAt(target);
				if (wrong != null && !hasCallReference(target)) {
					removeFunction(wrong);
					removed++;
				}
				if (getInstructionAt(target) == null) {
					new DisassembleCommand(target, null, true).applyTo(currentProgram, monitor);
				}
				currentProgram.getReferenceManager().addMemoryReference(jmp.getAddress(), target,
					RefType.COMPUTED_JUMP, SourceType.ANALYSIS, Reference.MNEMONIC);
			}
			Function owner = getFunctionContaining(jmp.getAddress());
			if (owner != null) {
				touched.add(owner);
			}
		}
		for (Function f : touched) {
			CreateFunctionCmd.fixupFunctionBody(currentProgram, f, monitor);
		}
		if (tables > 0) {
			println(String.format("Switch tables in code: %d, %d wrong case functions removed", tables, removed));
		}
		return tables;
	}

	private boolean hasCallReference(Address target) {
		for (Reference r : getReferencesTo(target)) {
			if (r.getReferenceType().isCall()) {
				return true;
			}
		}
		return false;
	}
}

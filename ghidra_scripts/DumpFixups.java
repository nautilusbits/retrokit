// Dumps every applied 32-bit LE fixup as "source -> target [kind] [string]" so
// pointer tables (function tables, message tables) can be studied offline.
//@category RetroKit
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Iterator;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;

public class DumpFixups extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args.length > 0 ? args[0] : "fixups.txt");
		MemoryBlock code = currentProgram.getMemory().getBlock(".object1");
		int n = 0;
		try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
			Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
			while (it.hasNext()) {
				Relocation r = it.next();
				if (r.getStatus() != Relocation.Status.APPLIED) {
					continue;
				}
				Address src = r.getAddress();
				String kind;
				String desc = "";
				long value;
				try {
					if (r.getType() == 7) {
						value = currentProgram.getMemory().getInt(src) & 0xffffffffL;
					}
					else if (r.getType() == 5 || r.getType() == 2) {
						value = currentProgram.getMemory().getShort(src) & 0xffffL;
					}
					else {
						continue;
					}
				}
				catch (Exception e) {
					continue;
				}
				Address target = src.getNewAddress(value);
				Function f = currentProgram.getFunctionManager().getFunctionContaining(target);
				if (f != null) {
					kind = f.getEntryPoint().equals(target) ? "FUNC" : "INFUNC";
					desc = f.getName();
				}
				else if (code != null && code.contains(target)) {
					kind = "CODE?";
				}
				else {
					kind = "DATA";
					Data d = currentProgram.getListing().getDataContaining(target);
					if (d != null && d.hasStringValue()) {
						desc = "\"" + String.valueOf(d.getValue()).replace("\n", "\\n") + "\"";
					}
					else if (d != null) {
						desc = d.getDataType().getName();
					}
				}
				Function from = currentProgram.getFunctionManager().getFunctionContaining(src);
				w.printf("%s\t%s\t%d\t%s\t%s\t%s%n", src, target, r.getType(), kind,
					from == null ? "-" : from.getName(), desc);
				n++;
			}
		}
		println("Wrote " + n + " fixups to " + out.getAbsolutePath());
	}
}

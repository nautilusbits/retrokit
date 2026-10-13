// Writes the function list (addr,name,size) without decompiling anything - what
// tools/find_entries.py needs between the entry passes of the PE pipeline.
//   -postScript DumpFunctions.java <out.csv>
//@category RetroKit
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class DumpFunctions extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args.length > 0 ? args[0] : "functions.csv");
		int n = 0;
		try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
			w.println("addr,name,size");
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				w.printf("%s,%s,%d%n", f.getEntryPoint(), f.getName(), f.getBody().getNumAddresses());
				n++;
			}
		}
		println("DumpFunctions: " + n + " functions -> " + out.getAbsolutePath());
	}
}

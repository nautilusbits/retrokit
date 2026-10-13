// Dumps PE imports (external symbols) and the thunk/IAT slots that reference them:
//   <out>  - lines "iat_addr\tLIB\tname\trefs" (+ "entry\tVA" for the entry point)
// Usage (headless): -postScript DumpImports.java <outputFile>
//@category RetroKit
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;

public class DumpImports extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args.length > 0 ? args[0] : "imports.txt");
		SymbolTable st = currentProgram.getSymbolTable();
		ReferenceManager rm = currentProgram.getReferenceManager();
		int n = 0;
		try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
			SymbolIterator it = st.getExternalSymbols();
			while (it.hasNext()) {
				Symbol s = it.next();
				String lib = s.getParentNamespace().getName();
				Address a = s.getAddress();
				// references *to* the external symbol = IAT slot(s)
				StringBuilder slots = new StringBuilder();
				for (Reference r : rm.getReferencesTo(a)) {
					if (slots.length() > 0) slots.append(',');
					slots.append(r.getFromAddress());
				}
				w.printf("%s\t%s\t%s%n", lib, s.getName(), slots);
				n++;
			}
			SymbolIterator ep = st.getSymbols("entry");
			while (ep.hasNext()) {
				w.printf("entry\t%s%n", ep.next().getAddress());
			}
		}
		println("DumpImports: " + n + " imports -> " + out.getAbsolutePath());
	}
}

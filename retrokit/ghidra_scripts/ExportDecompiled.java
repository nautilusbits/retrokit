// Exports everything we need from an analyzed program for offline study:
//   <out>/<cFileName>           - decompiled C of every function, by address
//                                 (2nd script arg, default decompiled.c)
//   <out>/functions.csv         - addr,name,size,callers,callees,cc
//   <out>/strings.txt           - defined strings with addresses
//   <out>/calls.txt             - caller -> callee edges
//   <out>/data_symbols.txt      - named data symbols with type and refs
//   <out>/memory_blocks.txt     - name, start, end, rwx of every memory block
// Usage (headless): -postScript ExportDecompiled.java <outputDir> [cFileName]
//@category RetroKit
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ExportDecompiled extends GhidraScript {

	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args.length > 0 ? args[0] : "decomp");
		String cFile = args.length > 1 ? args[1] : "decompiled.c";
		out.mkdirs();

		try (PrintWriter mb = new PrintWriter(new FileWriter(new File(out, "memory_blocks.txt")))) {
			// perm flags as set by the loader (LE loader leaves x/w unset); "functions" = number of
			// function entry points in the block, 0 for data objects
			mb.println("name\tstart\tend\tperm\tinitialized\tfunctions");
			for (ghidra.program.model.mem.MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				int nf = 0;
				if (b.getStart().isMemoryAddress() && b.isLoaded()) {
					for (Function f : currentProgram.getFunctionManager().getFunctions(
							new ghidra.program.model.address.AddressSet(b.getStart(), b.getEnd()), true)) {
						nf++;
					}
				}
				mb.printf("%s\t%s\t%s\t%s%s%s\t%s\t%d%n", b.getName(), b.getStart(), b.getEnd(),
					b.isRead() ? "r" : "-", b.isWrite() ? "w" : "-", b.isExecute() ? "x" : "-",
					b.isInitialized(), nf);
			}
		}

		FunctionManager fm = currentProgram.getFunctionManager();
		ReferenceManager rm = currentProgram.getReferenceManager();
		Listing listing = currentProgram.getListing();

		DecompInterface ifc = new DecompInterface();
		DecompileOptions opts = new DecompileOptions();
		ifc.setOptions(opts);
		ifc.toggleCCode(true);
		ifc.toggleSyntaxTree(false);
		ifc.setSimplificationStyle("decompile");
		if (!ifc.openProgram(currentProgram)) {
			printerr("Decompiler failed to open program: " + ifc.getLastMessage());
			return;
		}

		List<Function> funcs = new ArrayList<>();
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			funcs.add(f);
		}
		println("Exporting " + funcs.size() + " functions to " + out.getAbsolutePath());

		try (PrintWriter c = new PrintWriter(new FileWriter(new File(out, cFile)));
				PrintWriter idx = new PrintWriter(new FileWriter(new File(out, "functions.csv")));
				PrintWriter calls = new PrintWriter(new FileWriter(new File(out, "calls.txt")))) {

			idx.println("addr,name,size,callers,callees,cc,signature");
			int n = 0;
			for (Function f : funcs) {
				if (monitor.isCancelled()) {
					break;
				}
				monitor.setMessage("Decompiling " + f.getName() + " (" + (++n) + "/" + funcs.size() + ")");

				Set<Function> callees = f.getCalledFunctions(monitor);
				Set<Function> callers = f.getCallingFunctions(monitor);
				long size = f.getBody().getNumAddresses();
				idx.printf("%s,%s,%d,%d,%d,%s,\"%s\"%n", f.getEntryPoint(), f.getName(), size,
					callers.size(), callees.size(), f.getCallingConventionName(),
					f.getSignature().getPrototypeString().replace("\"", "'"));
				for (Function callee : callees) {
					calls.printf("%s %s -> %s %s%n", f.getEntryPoint(), f.getName(),
						callee.getEntryPoint(), callee.getName());
				}

				c.println("// ==================================================================");
				c.printf("// %s @ %s  size=%d  callers=%d  callees=%d%n", f.getName(),
					f.getEntryPoint(), size, callers.size(), callees.size());
				c.println("// ==================================================================");
				DecompileResults res = ifc.decompileFunction(f, 120, monitor);
				if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
					c.println(res.getDecompiledFunction().getC());
				}
				else {
					c.println("// DECOMPILE FAILED: " + (res == null ? "null" : res.getErrorMessage()));
				}
				c.println();
			}
		}
		ifc.dispose();

		try (PrintWriter s = new PrintWriter(new FileWriter(new File(out, "strings.txt")))) {
			for (Data d : listing.getDefinedData(true)) {
				if (d.hasStringValue()) {
					Object v = d.getValue();
					s.printf("%s\t%s\t%s%n", d.getAddress(), d.getDataType().getName(),
						String.valueOf(v).replace("\n", "\\n").replace("\r", "\\r"));
				}
			}
		}

		try (PrintWriter ds = new PrintWriter(new FileWriter(new File(out, "data_symbols.txt")))) {
			SymbolTable st = currentProgram.getSymbolTable();
			for (Symbol sym : st.getAllSymbols(false)) {
				if (sym.getSymbolType() != SymbolType.LABEL) {
					continue;
				}
				Address a = sym.getAddress();
				if (fm.getFunctionAt(a) != null) {
					continue;
				}
				Data d = listing.getDataAt(a);
				DataType dt = d == null ? null : d.getDataType();
				int refs = rm.getReferenceCountTo(a);
				ds.printf("%s\t%s\t%s\t%d refs%n", a, sym.getName(),
					dt == null ? "?" : dt.getName() + "[" + d.getLength() + "]", refs);
			}
		}
		println("Export done.");
	}
}

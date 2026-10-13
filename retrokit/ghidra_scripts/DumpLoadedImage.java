// Dumps what a loader produced, for comparing loaders and for the loader tests:
// memory blocks (name, range, permissions, SHA-1 of the bytes), relocations (address,
// type, status, the 1..4 bytes now at the address), entry points, external locations.
// Run right after an import without analysis:
//   -import GAME.EXE -loader X -noanalysis -postScript DumpLoadedImage.java <out.txt>
//@category RetroKit
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.TreeSet;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;

public class DumpLoadedImage extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String[] args = getScriptArgs();
		File out = new File(args.length > 0 ? args[0] : "loaded_image.txt");
		try (PrintWriter w = new PrintWriter(new FileWriter(out))) {
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				if (b.isOverlay()) {
					continue; // raw image / header markup differs between loaders by design
				}
				String sha = "-";
				if (b.isInitialized()) {
					byte[] bytes = new byte[(int) b.getSize()];
					b.getBytes(b.getStart(), bytes);
					StringBuilder sb = new StringBuilder();
					for (byte x : MessageDigest.getInstance("SHA-1").digest(bytes)) {
						sb.append(String.format("%02x", x));
					}
					sha = sb.toString();
				}
				w.printf("block %s %s %s %s%s%s %s%n", b.getName(), b.getStart(), b.getEnd(),
					b.isRead() ? "r" : "-", b.isWrite() ? "w" : "-", b.isExecute() ? "x" : "-", sha);
			}
			TreeSet<String> relocs = new TreeSet<>();
			Iterator<Relocation> it = currentProgram.getRelocationTable().getRelocations();
			while (it.hasNext()) {
				Relocation r = it.next();
				Address a = r.getAddress();
				String now;
				try {
					now = String.format("%08x", currentProgram.getMemory().getInt(a) & 0xffffffffL);
				}
				catch (Exception e) {
					now = "?";
				}
				relocs.add(String.format("reloc %s %d %s %s", a, r.getType(), r.getStatus(), now));
			}
			for (String s : relocs) {
				w.println(s);
			}
			for (Address a : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
				w.printf("entry %s %s%n", a, getSymbolAt(a) == null ? "-" : getSymbolAt(a).getName());
			}
			for (String lib : currentProgram.getExternalManager().getExternalLibraryNames()) {
				ExternalLocationIterator ei = currentProgram.getExternalManager().getExternalLocations(lib);
				while (ei.hasNext()) {
					ExternalLocation e = ei.next();
					w.printf("external %s %s%n", lib, e.getLabel());
				}
			}
		}
		println("DumpLoadedImage: " + out.getAbsolutePath());
	}
}

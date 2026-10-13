// Applies name proposals from analysis notes to the program: CSV files with header
// "addr,name,confidence,comment" (addr = hex, name = C identifier, confidence V/G).
//   * address with a function entry -> function renamed, plate comment "[V|G] comment"
//   * any other address             -> primary label created/renamed, EOL-less plate comment
// Rows are applied in file order; for an address named twice the V row wins over G,
// otherwise the first row wins. A name already used at another address gets "_<addr>".
// Usage (headless): -postScript ApplyNames.java <csv or directory of names_*.csv> [...]
//@category RetroKit
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class ApplyNames extends GhidraScript {

	private static final Pattern IDENT = Pattern.compile("[A-Za-z_][A-Za-z0-9_]{0,120}");

	private record Row(Address addr, String name, String conf, String comment, String source) {}

	@Override
	protected void run() throws Exception {
		List<File> files = new ArrayList<>();
		for (String a : getScriptArgs()) {
			File f = new File(a);
			if (f.isDirectory()) {
				File[] list = f.listFiles((d, n) -> n.startsWith("names_") && n.endsWith(".csv"));
				if (list != null) {
					Arrays.sort(list);
					files.addAll(Arrays.asList(list));
				}
			}
			else if (f.isFile()) {
				files.add(f);
			}
		}
		Map<Address, Row> chosen = new LinkedHashMap<>();
		int rows = 0, bad = 0;
		for (File f : files) {
			for (String line : Files.readAllLines(f.toPath(), StandardCharsets.UTF_8)) {
				List<String> cols = splitCsv(line);
				if (cols.size() < 2 || cols.get(0).equalsIgnoreCase("addr")) {
					continue;
				}
				rows++;
				String name = cols.get(1).trim();
				String conf = cols.size() > 2 ? cols.get(2).trim().toUpperCase() : "G";
				String comment = cols.size() > 3 ? cols.get(3).trim() : "";
				Address addr;
				try {
					addr = toAddr(Long.parseLong(cols.get(0).trim().replaceFirst("^(0x|0X)", ""), 16));
				}
				catch (Exception e) {
					bad++;
					continue;
				}
				if (!IDENT.matcher(name).matches() || !currentProgram.getMemory().contains(addr)) {
					bad++;
					continue;
				}
				Row r = new Row(addr, name, conf, comment, f.getName());
				Row old = chosen.get(addr);
				if (old == null || (!"V".equals(old.conf()) && "V".equals(conf))) {
					chosen.put(addr, r);
				}
			}
		}
		SymbolTable st = currentProgram.getSymbolTable();
		int funcs = 0, labels = 0, renamedDup = 0;
		for (Row r : chosen.values()) {
			String name = r.name();
			List<Symbol> same = st.getGlobalSymbols(name);
			boolean clash = same.stream().anyMatch(s -> !s.getAddress().equals(r.addr()));
			if (clash) {
				name = name + "_" + r.addr().toString();
				renamedDup++;
			}
			String plate = "[" + r.conf() + "] " + r.name() +
				(r.comment().isEmpty() ? "" : " - " + r.comment()) + " (" + r.source() + ")";
			Function fn = getFunctionAt(r.addr());
			if (fn != null) {
				fn.setName(name, SourceType.USER_DEFINED);
				currentProgram.getListing().setComment(r.addr(), CommentType.PLATE, plate);
				funcs++;
			}
			else {
				Symbol s = st.getPrimarySymbol(r.addr());
				if (s != null && s.getSource() != SourceType.DEFAULT) {
					s.setName(name, SourceType.USER_DEFINED);
				}
				else {
					st.createLabel(r.addr(), name, SourceType.USER_DEFINED).setPrimary();
				}
				currentProgram.getListing().setComment(r.addr(), CommentType.PLATE, plate);
				labels++;
			}
		}
		println(String.format("ApplyNames: %d rows from %d files, %d invalid, %d functions renamed, %d labels, %d name clashes suffixed",
			rows, files.size(), bad, funcs, labels, renamedDup));
	}

	private static List<String> splitCsv(String line) {
		List<String> out = new ArrayList<>();
		StringBuilder cur = new StringBuilder();
		boolean q = false;
		for (int i = 0; i < line.length(); i++) {
			char c = line.charAt(i);
			if (q) {
				if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
					cur.append('"');
					i++;
				}
				else if (c == '"') {
					q = false;
				}
				else {
					cur.append(c);
				}
			}
			else if (c == '"') {
				q = true;
			}
			else if (c == ',') {
				out.add(cur.toString());
				cur.setLength(0);
			}
			else {
				cur.append(c);
			}
		}
		out.add(cur.toString());
		return out;
	}
}

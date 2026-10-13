/* Copyright 2026 The retro-kit authors. Licensed under the Apache License, Version 2.0. */
package retrokit.le;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Loader for Linear Executables: DOS extender programs (DOS/4GW, DOS/32A, PMODE/W, CauseWay;
 * also DOS/4G "BW"-bound), OS/2 LX modules and Windows VxDs.
 *
 * Every object becomes a block ".objectN" at its base address (objects without one go to
 * N * 0x100000) with the object's read/write/execute permissions - read-only data would make
 * the decompiler fold globals into their initial values. All fixups are applied and recorded
 * in the relocation table (type = LE source type, status APPLIED, value = the written value),
 * which the retro-kit scripts use to find pointer tables. Imports become external locations,
 * exports labels, the entry point "_entry". The raw file is mapped as the overlay ".image"
 * with typed MZ / BW / LE headers and the object table.
 */
public class LinearExecutableLoader extends AbstractProgramWrapperLoader {

	public static final String NAME = "Linear Executable (retro-kit)";
	static final String OPTION_BASES = "Object base addresses (hex, comma separated)";
	private static final String LANGUAGE = "x86:LE:32:default";
	// Watcom first: DOS extender programs are almost always Watcom C/C++
	private static final String[] CSPECS = { "watcom", "watcomreg", "borlandcpp", "windows", "gcc" };

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.SPECIALIZED_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		return 0;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> specs = new ArrayList<>();
		if (provider.length() < 0x40 || !LinearImage.isLinear(provider)) {
			return specs;
		}
		for (int i = 0; i < CSPECS.length; i++) {
			specs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANGUAGE, CSPECS[i]), i == 0));
		}
		return specs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
			boolean isLoadIntoProgram, boolean mirrorFsLayout) {
		List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram,
			mirrorFsLayout);
		list.add(new Option(OPTION_BASES, ""));
		return list;
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
		for (Option o : options) {
			if (o.getName().equals(OPTION_BASES)) {
				try {
					parseBases(String.valueOf(o.getValue()));
				}
				catch (NumberFormatException e) {
					return "Object base addresses: " + e.getMessage();
				}
			}
		}
		return super.validateOptions(provider, loadSpec, options, program);
	}

	private static long[] parseBases(String s) {
		if (s == null || s.isBlank()) {
			return new long[0];
		}
		String[] parts = s.split(",");
		long[] out = new long[parts.length];
		for (int i = 0; i < parts.length; i++) {
			String p = parts[i].trim().toLowerCase().replaceFirst("^0x", "");
			out[i] = p.isEmpty() ? 0 : Long.parseLong(p, 16);
		}
		return out;
	}

	@Override
	protected void load(Program program, ImporterSettings settings) throws CancelledException, IOException {
		TaskMonitor monitor = settings.monitor();
		MessageLog log = settings.log();
		String bases = "";
		for (Option o : settings.options()) {
			if (o.getName().equals(OPTION_BASES)) {
				bases = String.valueOf(o.getValue());
			}
		}
		LinearImage le = new LinearImage(settings.provider());
		new Mapper(program, le, parseBases(bases), log, monitor).run(settings.provider());
	}

	/** One load: maps the image into the program. */
	private static class Mapper {
		final Program program;
		final LinearImage le;
		final long[] baseOverride;
		final MessageLog log;
		final TaskMonitor monitor;
		final AddressSpace space;
		final Map<Integer, Long> bases = new HashMap<>();
		final int[] applied = new int[16], unsupported = new int[16];

		Mapper(Program program, LinearImage le, long[] baseOverride, MessageLog log, TaskMonitor monitor) {
			this.program = program;
			this.le = le;
			this.baseOverride = baseOverride;
			this.log = log;
			this.monitor = monitor;
			this.space = program.getAddressFactory().getDefaultAddressSpace();
			for (LinearImage.ObjectEntry o : le.objects) {
				long b = o.number <= baseOverride.length && baseOverride[o.number - 1] != 0
						? baseOverride[o.number - 1] : (o.base != 0 ? o.base : o.number * 0x100000L);
				bases.put(o.number, b);
			}
		}

		void run(ByteProvider provider) throws IOException, CancelledException {
			log.appendMsg(String.format("%s image, header at 0x%x%s, %d objects, %d pages, %d fixups",
				le.signature, le.headerOffset, le.mzBase != 0 ? String.format(" (DOS/4G bind, MZ at 0x%x)", le.mzBase) : "",
				le.objects.size(), le.pages.size(), le.fixups.size()));
			mapImage(provider);
			Map<Integer, byte[]> data = new TreeMap<>();
			Map<Long, Object[]> relocs = new TreeMap<>();   // address -> {type, status, value, original bytes}
			for (LinearImage.ObjectEntry o : le.objects) {
				data.put(o.number, le.objectBytes(o));
			}
			applyFixups(data, relocs);
			for (LinearImage.ObjectEntry o : le.objects) {
				monitor.checkCancelled();
				createBlock(o, data.get(o.number));
			}
			recordRelocations(relocs);
			createExports();
			createEntry();
			StringBuilder sb = new StringBuilder("fixups applied:");
			for (int t = 0; t < 16; t++) {
				if (applied[t] > 0) {
					sb.append(String.format(" %s %d", name(t), applied[t]));
				}
			}
			for (int t = 0; t < 16; t++) {
				if (unsupported[t] > 0) {
					sb.append(String.format(", unsupported %s %d", name(t), unsupported[t]));
				}
			}
			log.appendMsg(sb.toString());
			program.setExecutableFormat(NAME);
		}

		static String name(int t) {
			return t < LinearImage.SOURCE_NAMES.length ? LinearImage.SOURCE_NAMES[t] : "type" + t;
		}

		long base(int object) {
			Long b = bases.get(object);
			return b == null ? 0 : b;
		}

		/** linear target of an internal or entry-table fixup, or -1 */
		long target(LinearImage.Fixup f) {
			if (f.targetType == LinearImage.TGT_INTERNAL) {
				return base(f.targetObject) + f.targetOffset + f.additive;
			}
			if (f.targetType == LinearImage.TGT_ENTRY) {
				LinearImage.EntryPoint e = le.entries.get(f.targetObject);
				if (e != null && !e.forwarder) {
					return base(e.object) + e.offset + f.additive;
				}
			}
			return -1;
		}

		int selector(LinearImage.Fixup f) {
			int obj = f.targetObject;
			if (f.targetType == LinearImage.TGT_ENTRY) {
				LinearImage.EntryPoint e = le.entries.get(f.targetObject);
				obj = e == null ? 0 : e.object;
			}
			return Math.max(obj - 1, 0);     // the object index, as a placeholder selector
		}

		static void put(byte[] b, long at, long value, int n) {
			for (int i = 0; i < n; i++) {
				if (at + i >= 0 && at + i < b.length) {
					b[(int) (at + i)] = (byte) (value >> (8 * i));
				}
			}
		}

		void applyFixups(Map<Integer, byte[]> data, Map<Long, Object[]> relocs) throws IOException {
			for (LinearImage.Fixup f : le.fixups) {
				LinearImage.ObjectEntry o = le.objectOfPage(f.page);
				if (o == null) {
					continue;
				}
				byte[] b = data.get(o.number);
				long at = (long) (f.page - o.firstPage) * le.pageSize + f.sourceOffset;  // offset in the object
				long addr = base(o.number) + at;
				byte[] original = new byte[sourceSize(f.sourceType)];
				for (int i = 0; i < original.length; i++) {
					original[i] = at + i >= 0 && at + i < b.length ? b[(int) (at + i)] : 0;
				}
				long t = target(f);
				if (t < 0) {
					unsupported[f.sourceType]++;
					importReference(f, addr);
					relocs.putIfAbsent(addr, new Object[] { f.sourceType, Relocation.Status.UNSUPPORTED, 0L, original });
					continue;
				}
				long value;
				switch (f.sourceType) {
					case LinearImage.SRC_BYTE:
						value = t & 0xff;
						put(b, at, value, 1);
						break;
					case LinearImage.SRC_OFFSET16:
						value = t & 0xffff;
						put(b, at, value, 2);
						break;
					case LinearImage.SRC_OFFSET32:
						value = t & 0xffffffffL;
						put(b, at, value, 4);
						break;
					case LinearImage.SRC_SELFREL32:
						value = (t - (addr + 4)) & 0xffffffffL;
						put(b, at, value, 4);
						break;
					case LinearImage.SRC_SELECTOR16:
						value = selector(f);
						put(b, at, value, 2);
						break;
					case LinearImage.SRC_PTR1616:
						value = (f.targetOffset & 0xffff) | ((long) selector(f) << 16);
						put(b, at, value, 4);
						break;
					case LinearImage.SRC_PTR1632:
						value = t & 0xffffffffL;
						put(b, at, value, 4);
						put(b, at + 4, selector(f), 2);
						break;
					default:
						unsupported[f.sourceType]++;
						relocs.putIfAbsent(addr, new Object[] { f.sourceType, Relocation.Status.UNSUPPORTED, 0L, original });
						continue;
				}
				applied[f.sourceType]++;
				// a fixup crossing a page boundary is listed for both pages: record it once
				relocs.putIfAbsent(addr, new Object[] { f.sourceType, Relocation.Status.APPLIED, value, original });
			}
		}

		static int sourceSize(int type) {
			switch (type) {
				case LinearImage.SRC_BYTE:
					return 1;
				case LinearImage.SRC_SELECTOR16:
				case LinearImage.SRC_OFFSET16:
					return 2;
				case LinearImage.SRC_PTR1632:
					return 6;
				default:
					return 4;
			}
		}

		final List<Object[]> pendingImports = new ArrayList<>();   // {address, module, name}

		void importReference(LinearImage.Fixup f, long addr) throws IOException {
			if (f.targetType != LinearImage.TGT_IMPORT_ORDINAL && f.targetType != LinearImage.TGT_IMPORT_NAME) {
				return;
			}
			String module = f.targetObject >= 1 && f.targetObject <= le.importModules.size()
					? le.importModules.get(f.targetObject - 1) : "MODULE_" + f.targetObject;
			String name = f.targetType == LinearImage.TGT_IMPORT_NAME ? le.importName(f.targetOffset)
					: "Ordinal_" + f.targetOffset;
			pendingImports.add(new Object[] { addr, module, name });
		}

		void createBlock(LinearImage.ObjectEntry o, byte[] bytes) throws IOException {
			if (o.virtualSize == 0) {
				return;
			}
			try {
				MemoryBlock mb = program.getMemory().createInitializedBlock(".object" + o.number,
					space.getAddress(base(o.number)), new ByteArrayInputStream(bytes), o.virtualSize, monitor,
					false);
				mb.setRead(true);
				mb.setWrite(o.isWrite());
				mb.setExecute(o.isExec());
				mb.setComment(String.format("%s object %d flags %04x", le.signature, o.number, o.flags));
			}
			catch (Exception e) {
				throw new IOException("cannot map object " + o.number + ": " + e.getMessage(), e);
			}
		}

		void recordRelocations(Map<Long, Object[]> relocs) {
			for (Map.Entry<Long, Object[]> e : relocs.entrySet()) {
				Object[] v = e.getValue();
				Address a = space.getAddress(e.getKey());
				int type = (Integer) v[0];
				program.getRelocationTable().add(a, (Relocation.Status) v[1], type, new long[] { (Long) v[2] },
					(byte[]) v[3], null);
			}
			for (Object[] imp : pendingImports) {
				try {
					Address from = space.getAddress((Long) imp[0]);
					ExternalLocation ext = program.getExternalManager().addExtLocation((String) imp[1],
						(String) imp[2], null, SourceType.IMPORTED);
					program.getReferenceManager().addExternalReference(from, 0, ext, SourceType.IMPORTED, RefType.DATA);
				}
				catch (Exception ex) {
					log.appendMsg("import " + imp[1] + "." + imp[2] + ": " + ex.getMessage());
				}
			}
		}

		void createExports() {
			for (LinearImage.EntryPoint e : le.entries.values()) {
				if (e.forwarder || e.name == null || bases.get(e.object) == null) {
					continue;
				}
				try {
					Address a = space.getAddress(base(e.object) + e.offset);
					program.getSymbolTable().createLabel(a, e.name, SourceType.IMPORTED);
					program.getSymbolTable().addExternalEntryPoint(a);
				}
				catch (Exception ex) {
					log.appendMsg("export " + e.name + ": " + ex.getMessage());
				}
			}
		}

		void createEntry() {
			if (le.eipObject == 0 || bases.get((int) le.eipObject) == null) {
				return;
			}
			Address a = space.getAddress(base((int) le.eipObject) + le.eip);
			try {
				FlatProgramAPI api = new FlatProgramAPI(program, monitor);
				program.getSymbolTable().createLabel(a, "_entry", SourceType.IMPORTED);
				api.addEntryPoint(a);
				api.disassemble(a);
				api.createFunction(a, "_entry");
			}
			catch (Exception ex) {
				log.appendMsg("entry point: " + ex.getMessage());
			}
		}

		// ---------------------------------------------------------------- raw image overlay

		void mapImage(ByteProvider provider) throws IOException, CancelledException {
			try {
				FileBytes fb = MemoryBlockUtils.createFileBytes(program, provider, monitor);
				MemoryBlock b = MemoryBlockUtils.createInitializedBlock(program, true, ".image",
					AddressSpace.OTHER_SPACE.getAddress(0), fb, 0, fb.getSize(), "raw file image", null, false,
					false, false, log);
				Address img = b.getStart();
				if (le.headerOffset >= 0x40 || le.mzBase > 0) {
					markup(img, mzHeader(), "IMG_MZ_HEADER");
				}
				for (long bw : le.bwHeaders) {
					markup(img.add(bw), bwHeader(), String.format("IMG_%08X_BW_HEADER", bw));
				}
				if (le.mzBase > 0) {
					markup(img.add(le.mzBase), mzHeader(), String.format("IMG_%08X_MZ_HEADER", le.mzBase));
				}
				markup(img.add(le.headerOffset), leHeader(), String.format("IMG_%08X_%s_HEADER", le.headerOffset,
					le.signature));
				if (le.objectCount > 0) {
					markup(img.add(le.headerOffset + le.objectTableOffset),
						new ArrayDataType(objectEntry(), (int) le.objectCount, 24), "IMG_OBJECT_TABLE");
				}
			}
			catch (CancelledException e) {
				throw e;
			}
			catch (Exception e) {
				log.appendMsg("image overlay: " + e.getMessage());
			}
		}

		void markup(Address a, DataType dt, String label) {
			try {
				program.getListing().createData(a, dt);
				program.getSymbolTable().createLabel(a, label, SourceType.IMPORTED);
			}
			catch (Exception e) {
				log.appendMsg("markup " + label + ": " + e.getMessage());
			}
		}

		static StructureDataType mzHeader() {
			StructureDataType s = new StructureDataType("IMAGE_MZ_HEADER", 0);
			String[] w = { "e_magic", "e_cblp", "e_cp", "e_crlc", "e_cparhdr", "e_minalloc", "e_maxalloc", "e_ss",
				"e_sp", "e_csum", "e_ip", "e_cs", "e_lfarlc", "e_ovno" };
			for (String n : w) {
				s.add(WordDataType.dataType, n, null);
			}
			s.add(new ArrayDataType(WordDataType.dataType, 4, 2), "e_res", null);
			s.add(WordDataType.dataType, "e_oemid", null);
			s.add(WordDataType.dataType, "e_oeminfo", null);
			s.add(new ArrayDataType(WordDataType.dataType, 10, 2), "e_res2", null);
			s.add(DWordDataType.dataType, "e_lfanew", null);
			return s;
		}

		static StructureDataType bwHeader() {
			StructureDataType s = new StructureDataType("IMAGE_BW_HEADER", 0);
			s.add(new StringDataType(), 2, "signature", "BW (DOS/4G bind)");
			s.add(new ArrayDataType(ByteDataType.dataType, 0x1a, 1), "data", null);
			s.add(DWordDataType.dataType, "next_header", "file offset of the next BW header / the MZ of the bound program");
			return s;
		}

		static StructureDataType leHeader() {
			StructureDataType s = new StructureDataType("IMAGE_LE_HEADER", 0);
			s.add(new StringDataType(), 2, "signature", null);
			s.add(ByteDataType.dataType, "byte_order", null);
			s.add(ByteDataType.dataType, "word_order", null);
			s.add(DWordDataType.dataType, "format_level", null);
			s.add(WordDataType.dataType, "cpu_type", null);
			s.add(WordDataType.dataType, "os_type", null);
			String[] d = { "module_version", "module_flags", "page_count", "eip_object", "eip", "esp_object", "esp",
				"page_size", "last_page_size_or_shift", "fixup_section_size", "fixup_checksum", "loader_section_size",
				"loader_checksum", "object_table", "object_count", "object_page_map", "iterated_pages",
				"resource_table", "resource_count", "resident_names", "entry_table", "module_directives",
				"directive_count", "fixup_page_table", "fixup_records", "import_modules", "import_module_count",
				"import_procedures", "page_checksums", "data_pages", "preload_pages", "nonresident_names",
				"nonresident_names_size", "nonresident_checksum", "auto_data_object", "debug_info",
				"debug_info_size", "instance_preload", "instance_demand", "heap_size" };
			for (String n : d) {
				s.add(DWordDataType.dataType, n, null);
			}
			return s;
		}

		static StructureDataType objectEntry() {
			StructureDataType s = new StructureDataType("IMAGE_LE_OBJECT", 0);
			for (String n : new String[] { "virtual_size", "base", "flags", "page_map_index", "page_count",
				"reserved" }) {
				s.add(DWordDataType.dataType, n, null);
			}
			return s;
		}
	}
}

/* Copyright 2026 The retro-kit authors. Licensed under the Apache License, Version 2.0. */
package retrokit.le;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;

/**
 * Parsed Linear Executable (LE / LX) image: header, object table, page map, fixups,
 * entry table and name tables. Independent of Ghidra's program model, so the loader
 * only has to map what this class describes.
 *
 * Where the header sits: behind a plain MZ stub (e_lfanew), behind a DOS/4G bind chain
 * ("BW" headers after an old-style MZ stub, then a second MZ whose e_lfanew points to the
 * LE; offsets such as the data pages are then relative to that second MZ), or at offset 0.
 */
public class LinearImage {

	/** Object table flags */
	public static final int OBJ_READ = 0x1, OBJ_WRITE = 0x2, OBJ_EXEC = 0x4, OBJ_RESOURCE = 0x8,
			OBJ_ZEROFILL = 0x100, OBJ_BIG = 0x2000;

	/** Fixup source types (low nibble of the source byte) */
	public static final int SRC_BYTE = 0, SRC_SELECTOR16 = 2, SRC_PTR1616 = 3, SRC_OFFSET16 = 5,
			SRC_PTR1632 = 6, SRC_OFFSET32 = 7, SRC_SELFREL32 = 8;
	/** Fixup target types (low two bits of the flags byte) */
	public static final int TGT_INTERNAL = 0, TGT_IMPORT_ORDINAL = 1, TGT_IMPORT_NAME = 2, TGT_ENTRY = 3;

	public static final String[] SOURCE_NAMES = { "byte", "?1", "sel16", "ptr16_16", "?4", "off16", "ptr16_32",
		"off32", "rel32" };

	public static class ObjectEntry {
		public int number;           // 1-based
		public long virtualSize, base, flags;
		public int firstPage, pageCount; // first page index is 1-based

		public boolean isRead() { return (flags & OBJ_READ) != 0; }
		public boolean isWrite() { return (flags & OBJ_WRITE) != 0; }
		public boolean isExec() { return (flags & OBJ_EXEC) != 0; }
	}

	public static class PageEntry {
		public long fileOffset;      // absolute in the file
		public int size;             // bytes stored in the file
		public int type;             // 0 legal, 1 iterated, 2 invalid, 3 zero-filled, 4 range, 5 compressed
	}

	public static class Fixup {
		public int page;             // 1-based page whose record list holds it
		public int sourceType, sourceFlags, flags, targetType;
		public int sourceOffset;     // signed offset within the page (may be negative: crosses from the previous page)
		public int targetObject;     // internal: object number; import: module ordinal; entry: entry ordinal
		public long targetOffset;    // internal: offset in the object; import: ordinal or name offset
		public long additive;

		public boolean isAdditive() { return (flags & 0x4) != 0; }
		public String sourceName() {
			return sourceType < SOURCE_NAMES.length ? SOURCE_NAMES[sourceType] : "type" + sourceType;
		}
	}

	public static class EntryPoint {
		public int ordinal, object;
		public long offset;
		public boolean forwarder;
		public String name;
	}

	public final ByteProvider provider;
	public long headerOffset;        // absolute offset of the LE/LX header
	public long mzBase;              // MZ header the LE belongs to (0, or the second MZ of a BW chain)
	public final List<Long> bwHeaders = new ArrayList<>();
	public String signature;         // "LE" or "LX"
	public int cpuType, osType;
	public long moduleFlags, pageCount, eipObject, eip, espObject, esp, pageSize, lastPageOrShift;
	public long objectTableOffset, objectCount, pageMapOffset, iterPagesOffset, residentNamesOffset,
			entryTableOffset, fixupPageTableOffset, fixupRecordOffset, importModulesOffset, importModuleCount,
			importProcsOffset, dataPagesOffset, nonResidentNamesOffset, nonResidentNamesLength, autoDataObject,
			debugInfoOffset, debugInfoLength;

	public final List<ObjectEntry> objects = new ArrayList<>();
	public final List<PageEntry> pages = new ArrayList<>();      // index 0 = page 1
	public final List<Fixup> fixups = new ArrayList<>();
	public final List<String> importModules = new ArrayList<>();
	public final Map<Integer, EntryPoint> entries = new HashMap<>();
	public String moduleName;

	private final BinaryReader r;

	public LinearImage(ByteProvider provider) throws IOException {
		this.provider = provider;
		this.r = new BinaryReader(provider, true);
		locate();
		readHeader();
		readObjects();
		readPageMap();
		readFixups();
		readImportModules();
		readEntries();
		readNames();
	}

	/** true if the provider holds an LE/LX image this class can parse */
	public static boolean isLinear(ByteProvider provider) {
		try {
			new LinearImage(provider);
			return true;
		}
		catch (IOException | RuntimeException e) {
			return false;
		}
	}

	private boolean isHeader(long o) throws IOException {
		if (o < 0 || o + 0xb0 > provider.length()) {
			return false;
		}
		int a = r.readUnsignedByte(o), b = r.readUnsignedByte(o + 1);
		return ((a == 'L' && b == 'E') || (a == 'L' && b == 'X')) && r.readUnsignedByte(o + 2) == 0 &&
			r.readUnsignedByte(o + 3) == 0 && r.readUnsignedInt(o + 4) == 0;
	}

	private void locate() throws IOException {
		long len = provider.length();
		if (len >= 0x40 && r.readUnsignedShort(0) == 0x5a4d) {           // "MZ"
			long lfanew = r.readUnsignedInt(0x3c);
			if (r.readUnsignedShort(0x18) >= 0x40 && isHeader(lfanew)) {
				headerOffset = lfanew;
				mzBase = 0;
				return;
			}
			// old-style stub: the image continues after the stub's file size
			int cblp = r.readUnsignedShort(2), cp = r.readUnsignedShort(4);
			long o = cblp != 0 ? (cp - 1L) * 512 + cblp : cp * 512L;
			while (o + 0x20 <= len && r.readUnsignedShort(o) == 0x5742 && !bwHeaders.contains(o)) {   // "BW"
				bwHeaders.add(o);
				long next = r.readUnsignedInt(o + 0x1c);
				if (next <= o) {
					break;
				}
				o = next;
			}
			if (o + 0x40 <= len && r.readUnsignedShort(o) == 0x5a4d) {
				long le = o + r.readUnsignedInt(o + 0x3c);
				if (isHeader(le)) {
					headerOffset = le;
					mzBase = o;
					return;
				}
			}
		}
		else if (isHeader(0)) {
			headerOffset = 0;
			return;
		}
		throw new IOException("no LE/LX header");
	}

	private long h32(int off) throws IOException {
		return r.readUnsignedInt(headerOffset + off);
	}

	private void readHeader() throws IOException {
		signature = r.readAsciiString(headerOffset, 2);
		cpuType = r.readUnsignedShort(headerOffset + 0x08);
		osType = r.readUnsignedShort(headerOffset + 0x0a);
		moduleFlags = h32(0x10);
		pageCount = h32(0x14);
		eipObject = h32(0x18);
		eip = h32(0x1c);
		espObject = h32(0x20);
		esp = h32(0x24);
		pageSize = h32(0x28);
		lastPageOrShift = h32(0x2c);
		objectTableOffset = h32(0x40);
		objectCount = h32(0x44);
		pageMapOffset = h32(0x48);
		iterPagesOffset = h32(0x4c);
		residentNamesOffset = h32(0x58);
		entryTableOffset = h32(0x5c);
		fixupPageTableOffset = h32(0x68);
		fixupRecordOffset = h32(0x6c);
		importModulesOffset = h32(0x70);
		importModuleCount = h32(0x74);
		importProcsOffset = h32(0x78);
		dataPagesOffset = h32(0x80);
		nonResidentNamesOffset = h32(0x88);
		nonResidentNamesLength = h32(0x8c);
		autoDataObject = h32(0x94);
		debugInfoOffset = h32(0x98);
		debugInfoLength = h32(0x9c);
		if (pageSize == 0 || pageSize > 0x10000 || objectCount > 0x1000 || pageCount > 0x100000) {
			throw new IOException("implausible LE/LX header");
		}
	}

	public boolean isLX() {
		return "LX".equals(signature);
	}

	/** module type bits of the module flags: 0x00000 program, 0x08000 library, 0x28000 VxD (LE) */
	public boolean isVxD() {
		return !isLX() && (moduleFlags & 0x38000) == 0x28000;
	}

	private void readObjects() throws IOException {
		for (int i = 0; i < objectCount; i++) {
			long o = headerOffset + objectTableOffset + i * 24L;
			ObjectEntry e = new ObjectEntry();
			e.number = i + 1;
			e.virtualSize = r.readUnsignedInt(o);
			e.base = r.readUnsignedInt(o + 4);
			e.flags = r.readUnsignedInt(o + 8);
			e.firstPage = (int) r.readUnsignedInt(o + 12);
			e.pageCount = (int) r.readUnsignedInt(o + 16);
			objects.add(e);
		}
	}

	private void readPageMap() throws IOException {
		long data = mzBase + dataPagesOffset;
		for (int i = 0; i < pageCount; i++) {
			PageEntry p = new PageEntry();
			if (isLX()) {
				long o = headerOffset + pageMapOffset + i * 8L;
				p.fileOffset = data + (r.readUnsignedInt(o) << lastPageOrShift);
				p.size = r.readUnsignedShort(o + 4);
				p.type = r.readUnsignedShort(o + 6);
			}
			else {
				// LE: 24-bit big-endian page number + type byte; pages are stored in order
				long o = headerOffset + pageMapOffset + i * 4L;
				long number = (r.readUnsignedByte(o) << 16) | (r.readUnsignedByte(o + 1) << 8) | r.readUnsignedByte(o + 2);
				p.type = r.readUnsignedByte(o + 3);
				p.fileOffset = data + (number - 1) * pageSize;
				p.size = (int) (number == pageCount ? lastPageOrShift : pageSize);
			}
			pages.add(p);
		}
	}

	private void readFixups() throws IOException {
		if (fixupPageTableOffset == 0 || fixupRecordOffset == 0) {
			return;
		}
		long records = headerOffset + fixupRecordOffset;
		for (int page = 1; page <= pageCount; page++) {
			long start = r.readUnsignedInt(headerOffset + fixupPageTableOffset + (page - 1) * 4L);
			long end = r.readUnsignedInt(headerOffset + fixupPageTableOffset + page * 4L);
			long o = records + start;
			while (o < records + end) {
				o = readFixup(o, page);
			}
		}
	}

	private long readFixup(long o, int page) throws IOException {
		int src = r.readUnsignedByte(o++);
		int flags = r.readUnsignedByte(o++);
		Fixup f = new Fixup();
		f.page = page;
		f.sourceType = src & 0x0f;
		f.sourceFlags = src & 0xf0;
		f.flags = flags;
		f.targetType = flags & 0x3;
		boolean list = (src & 0x20) != 0;
		int count = 1;
		if (list) {
			count = r.readUnsignedByte(o++);
		}
		else {
			f.sourceOffset = r.readShort(o);
			o += 2;
		}
		boolean ord16 = (flags & 0x40) != 0;
		f.targetObject = ord16 ? r.readUnsignedShort(o) : r.readUnsignedByte(o);
		o += ord16 ? 2 : 1;
		switch (f.targetType) {
			case TGT_INTERNAL:
				if (f.sourceType != SRC_SELECTOR16) {
					if ((flags & 0x10) != 0) {
						f.targetOffset = r.readUnsignedInt(o);
						o += 4;
					}
					else {
						f.targetOffset = r.readUnsignedShort(o);
						o += 2;
					}
				}
				break;
			case TGT_IMPORT_ORDINAL:
				if ((flags & 0x80) != 0) {
					f.targetOffset = r.readUnsignedByte(o++);
				}
				else if ((flags & 0x10) != 0) {
					f.targetOffset = r.readUnsignedInt(o);
					o += 4;
				}
				else {
					f.targetOffset = r.readUnsignedShort(o);
					o += 2;
				}
				break;
			case TGT_IMPORT_NAME:
				if ((flags & 0x10) != 0) {
					f.targetOffset = r.readUnsignedInt(o);
					o += 4;
				}
				else {
					f.targetOffset = r.readUnsignedShort(o);
					o += 2;
				}
				break;
			default: // TGT_ENTRY: the ordinal was read as targetObject
				break;
		}
		if ((flags & 0x4) != 0) {
			if ((flags & 0x20) != 0) {
				f.additive = r.readUnsignedInt(o);
				o += 4;
			}
			else {
				f.additive = r.readUnsignedShort(o);
				o += 2;
			}
		}
		if (!list) {
			fixups.add(f);
			return o;
		}
		for (int i = 0; i < count; i++) {
			Fixup c = copy(f);
			c.sourceOffset = r.readShort(o);
			o += 2;
			fixups.add(c);
		}
		return o;
	}

	private static Fixup copy(Fixup f) {
		Fixup c = new Fixup();
		c.page = f.page;
		c.sourceType = f.sourceType;
		c.sourceFlags = f.sourceFlags;
		c.flags = f.flags;
		c.targetType = f.targetType;
		c.targetObject = f.targetObject;
		c.targetOffset = f.targetOffset;
		c.additive = f.additive;
		return c;
	}

	private void readImportModules() throws IOException {
		long o = headerOffset + importModulesOffset;
		for (int i = 0; importModulesOffset != 0 && i < importModuleCount; i++) {
			int n = r.readUnsignedByte(o);
			importModules.add(r.readAsciiString(o + 1, n));
			o += 1 + n;
		}
	}

	/** name of an import-by-name fixup (offset into the import procedure name table) */
	public String importName(long offset) throws IOException {
		long o = headerOffset + importProcsOffset + offset;
		int n = r.readUnsignedByte(o);
		return new String(r.readByteArray(o + 1, n), StandardCharsets.ISO_8859_1);
	}

	private void readEntries() throws IOException {
		if (entryTableOffset == 0) {
			return;
		}
		long o = headerOffset + entryTableOffset;
		int ordinal = 1;
		while (o < provider.length()) {
			int count = r.readUnsignedByte(o++);
			if (count == 0) {
				break;
			}
			int type = r.readUnsignedByte(o++);
			if (type == 0) {             // unused ordinals
				ordinal += count;
				continue;
			}
			int object = r.readUnsignedShort(o);
			o += 2;
			for (int i = 0; i < count; i++, ordinal++) {
				EntryPoint e = new EntryPoint();
				e.ordinal = ordinal;
				e.object = object;
				o += 1;                  // entry flags
				switch (type) {
					case 1:              // 16-bit
						e.offset = r.readUnsignedShort(o);
						o += 2;
						break;
					case 2:              // 286 call gate
						e.offset = r.readUnsignedShort(o);
						o += 4;
						break;
					case 3:              // 32-bit
						e.offset = r.readUnsignedInt(o);
						o += 4;
						break;
					case 4:              // forwarder (LX)
						e.forwarder = true;
						o += 6;
						break;
					default:
						throw new IOException("bad entry bundle type " + type);
				}
				entries.put(ordinal, e);
			}
		}
	}

	private void readNameTable(long o, long end) throws IOException {
		boolean first = moduleName == null;
		while (o < end) {
			int n = r.readUnsignedByte(o);
			if (n == 0) {
				break;
			}
			String name = new String(r.readByteArray(o + 1, n), StandardCharsets.ISO_8859_1);
			int ordinal = r.readUnsignedShort(o + 1 + n);
			o += 3 + n;
			if (first) {             // the first resident name is the module name
				moduleName = name;
				first = false;
				continue;
			}
			EntryPoint e = entries.get(ordinal);
			if (e != null && e.name == null) {
				e.name = name;
			}
		}
	}

	private void readNames() throws IOException {
		if (residentNamesOffset != 0) {
			readNameTable(headerOffset + residentNamesOffset, provider.length());
		}
		if (nonResidentNamesOffset != 0 && nonResidentNamesLength != 0) {
			// file offset (relative to the MZ the LE belongs to, like the data pages); the first
			// non-resident name is the module description
			long o = mzBase + nonResidentNamesOffset, end = o + nonResidentNamesLength;
			if (o < provider.length()) {
				o += 3 + r.readUnsignedByte(o);
				readNameTable(o, Math.min(end, provider.length()));
			}
		}
	}

	/** object of a 1-based page index, or null */
	public ObjectEntry objectOfPage(int page) {
		for (ObjectEntry e : objects) {
			if (page >= e.firstPage && page < e.firstPage + e.pageCount) {
				return e;
			}
		}
		return null;
	}

	/** Object contents as stored in the file: pages concatenated, zero-filled to the virtual size. */
	public byte[] objectBytes(ObjectEntry obj) throws IOException {
		long size = Math.max(obj.virtualSize, (long) obj.pageCount * pageSize);
		byte[] out = new byte[(int) size];
		for (int i = 0; i < obj.pageCount; i++) {
			int index = obj.firstPage + i;
			if (index < 1 || index > pages.size()) {
				break;
			}
			PageEntry p = pages.get(index - 1);
			int at = (int) (i * pageSize);
			if (p.type == 0 && p.size > 0) {
				int n = (int) Math.min(p.size, Math.min(pageSize, provider.length() - p.fileOffset));
				if (n > 0) {
					System.arraycopy(r.readByteArray(p.fileOffset, n), 0, out, at, n);
				}
			}
			else if (p.type == 1 && isLX()) {
				expandIterated(r.readByteArray(p.fileOffset, p.size), out, at, (int) pageSize);
			}
			// 2 invalid, 3 zero-filled, 4 range, 5 compressed (EXEPACK2, not supported): zeros
		}
		return out;
	}

	/** LX EXEPACK1 iterated page: records {u16 repeat, u16 length, bytes} */
	private static void expandIterated(byte[] src, byte[] out, int at, int max) {
		int s = 0, d = at, end = at + max;
		while (s + 4 <= src.length && d < end) {
			int repeat = (src[s] & 0xff) | (src[s + 1] & 0xff) << 8;
			int len = (src[s + 2] & 0xff) | (src[s + 3] & 0xff) << 8;
			s += 4;
			if (repeat == 0 || s + len > src.length) {
				break;
			}
			for (int k = 0; k < repeat && d < end; k++) {
				for (int j = 0; j < len && d < end; j++) {
					out[d++] = src[s + j];
				}
			}
			s += len;
		}
	}
}

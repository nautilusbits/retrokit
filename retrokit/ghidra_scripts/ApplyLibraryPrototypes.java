// Gives library functions their documented prototypes: every function whose name is declared
// in one of the given C headers (retrokit/knowledge/*.h) gets that signature, with the
// program's calling convention (Watcom register or stack convention; variadic functions take
// their arguments on the stack). The functions are tagged LIBRARY, which ApplyStackConvention
// and RecoverPrototypes leave alone.
//
// Prototypes with float/double parameters or results are skipped: how Watcom passes them
// (8087 stack, EDX:EAX, or the stack, depending on the -fp switch) is not modelled.
//   -preScript ApplyLibraryPrototypes.java <header.h> [...]
//@category RetroKit
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class ApplyLibraryPrototypes extends GhidraScript {

	public static final String TAG = "LIBRARY";

	@Override
	protected void run() throws Exception {
		FunctionManager fm = currentProgram.getFunctionManager();
		String defaultCc = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
		if (!defaultCc.startsWith("__watcall")) {
			println("ApplyLibraryPrototypes: not a Watcom compiler spec (" + defaultCc + "), nothing done");
			return;
		}
		String stackCc = fm.getCallingConvention("__watcall_stack") != null ? "__watcall_stack" : "__cdecl";

		Map<String, FunctionDefinition> protos = new HashMap<>();
		DataTypeManager dtm = currentProgram.getDataTypeManager();
		// one parse over all headers, in the given order: later headers use the C library's
		// types (size_t, FILE) from the first
		StringBuilder text = new StringBuilder();
		for (String a : getScriptArgs()) {
			text.append(Files.readString(new File(a).toPath(), StandardCharsets.UTF_8)).append('\n');
		}
		CParser parser = new CParser(dtm, true, null);
		parser.parse(text.toString());
		for (Map.Entry<String, DataType> e : parser.getFunctions().entrySet()) {
			if (e.getValue() instanceof FunctionDefinition fd) {
				protos.put(e.getKey(), fd);
			}
		}

		int applied = 0, skippedFloat = 0, failed = 0;
		for (Function f : fm.getFunctions(true)) {
			FunctionDefinition fd = protos.get(f.getName());
			if (fd == null || f.isExternal()) {
				continue;
			}
			if (usesFloat(fd)) {
				skippedFloat++;
				continue;
			}
			ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), fd, SourceType.IMPORTED);
			if (!cmd.applyTo(currentProgram, monitor)) {
				printerr("  " + f.getName() + ": " + cmd.getStatusMsg());
				failed++;
				continue;
			}
			f.setCallingConvention(fd.hasVarArgs() ? stackCc : defaultCc);
			f.addTag(TAG);
			applied++;
			if (NO_RETURN.contains(f.getName())) {
				f.setNoReturn(true);
			}
		}
		println("ApplyLibraryPrototypes: " + applied + " library functions typed from " + protos.size() +
			" prototypes (" + skippedFloat + " with floating point left to the decompiler, " + failed + " failed)");
	}

	private static final Set<String> NO_RETURN = Set.of("exit", "_exit", "abort", "longjmp");

	private static boolean usesFloat(FunctionDefinition fd) {
		if (isFloat(fd.getReturnType())) {
			return true;
		}
		for (ParameterDefinition p : fd.getArguments()) {
			if (isFloat(p.getDataType())) {
				return true;
			}
		}
		return false;
	}

	private static boolean isFloat(DataType t) {
		while (t instanceof TypeDef td) {
			t = td.getBaseDataType();
		}
		return t instanceof AbstractFloatDataType;
	}
}

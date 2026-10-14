// Gives library functions their documented prototypes from C headers (retrokit/knowledge).
//
// Watcom programs (LE/LX): every function whose name is declared in the headers gets that
// signature with the program's calling convention (Watcom register or stack convention;
// variadic functions take their arguments on the stack). Prototypes with float/double are
// skipped: how Watcom passes them (8087 stack, EDX:EAX, or the stack, depending on the -fp
// switch) is not modelled.
//
// Other programs (Win32 PE): the imported functions (Ghidra's external functions) whose
// undecorated name ("_AIL_startup@0" -> AIL_startup) is declared get the signature with the
// calling convention the header gives (__stdcall for the DLL APIs). For a decorated import
// "@N" must equal the argument bytes of the prototype, otherwise the version of the library
// differs and the prototype is left out.
//
// The functions are tagged LIBRARY, which ApplyStackConvention and RecoverPrototypes leave alone.
//   -preScript ApplyLibraryPrototypes.java <header.h> [...]     (one parse, in this order)
//@category RetroKit
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;

public class ApplyLibraryPrototypes extends GhidraScript {

	public static final String TAG = "LIBRARY";
	private static final Set<String> NO_RETURN = Set.of("exit", "_exit", "abort", "longjmp");
	private static final Pattern DECORATED = Pattern.compile("^(?:__imp_)?_?([A-Za-z_]\\w*?)(?:@(\\d+))?$");

	@Override
	protected void run() throws Exception {
		Map<String, FunctionDefinition> protos = parse(getScriptArgs());
		String defaultCc = currentProgram.getCompilerSpec().getDefaultCallingConvention().getName();
		if (defaultCc.startsWith("__watcall")) {
			watcom(protos, defaultCc);
		}
		else {
			imports(protos);
		}
	}

	private Map<String, FunctionDefinition> parse(String[] headers) throws Exception {
		// one parse over all headers, in the given order: later headers use the types of the
		// first (C library: size_t, FILE; Win32: DWORD, GUID)
		StringBuilder text = new StringBuilder();
		for (String a : headers) {
			text.append(Files.readString(new File(a).toPath(), StandardCharsets.UTF_8)).append('\n');
		}
		CParser parser = new CParser(currentProgram.getDataTypeManager(), true, null);
		parser.parse(text.toString());
		Map<String, FunctionDefinition> protos = new HashMap<>();
		for (Map.Entry<String, DataType> e : parser.getFunctions().entrySet()) {
			if (e.getValue() instanceof FunctionDefinition fd) {
				protos.put(e.getKey(), fd);
			}
		}
		return protos;
	}

	private void watcom(Map<String, FunctionDefinition> protos, String defaultCc) throws Exception {
		FunctionManager fm = currentProgram.getFunctionManager();
		String stackCc = fm.getCallingConvention("__watcall_stack") != null ? "__watcall_stack" : "__cdecl";
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
			if (!apply(f, fd)) {
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

	private void imports(Map<String, FunctionDefinition> protos) throws Exception {
		FunctionManager fm = currentProgram.getFunctionManager();
		int applied = 0, mismatch = 0, failed = 0;
		List<Function> targets = new ArrayList<>();
		fm.getExternalFunctions().forEach(targets::add);
		for (Function f : targets) {
			Matcher m = DECORATED.matcher(f.getName());
			if (!m.matches()) {
				continue;
			}
			FunctionDefinition fd = protos.get(m.group(1));
			if (fd == null) {
				continue;
			}
			if (m.group(2) != null && Integer.parseInt(m.group(2)) != argBytes(fd)) {
				println("  " + f.getName() + ": the prototype takes " + argBytes(fd) + " bytes of arguments - other " +
					"version of the library, left alone");
				mismatch++;
				continue;
			}
			if (!apply(f, fd)) {
				failed++;
				continue;
			}
			String cc = fd.getCallingConventionName();
			if (cc != null && !cc.equals(Function.UNKNOWN_CALLING_CONVENTION_STRING) &&
				!cc.equals(Function.DEFAULT_CALLING_CONVENTION_STRING)) {
				f.setCallingConvention(cc);
			}
			f.addTag(TAG);
			if (!f.getName().equals(m.group(1))) {
				// _SmackOpen@12 -> SmackOpen (the external location keeps the imported name)
				try {
					f.setName(m.group(1), SourceType.IMPORTED);
				}
				catch (Exception e) {
					// a function of that name exists already: keep the decorated one
				}
			}
			applied++;
		}
		println("ApplyLibraryPrototypes: " + applied + " imported functions typed from " + protos.size() +
			" prototypes (" + mismatch + " decorated with other argument sizes left alone, " + failed + " failed)");
	}

	private boolean apply(Function f, FunctionDefinition fd) {
		ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(f.getEntryPoint(), fd, SourceType.IMPORTED);
		if (cmd.applyTo(currentProgram, monitor)) {
			return true;
		}
		printerr("  " + f.getName() + ": " + cmd.getStatusMsg());
		return false;
	}

	/** bytes a __stdcall callee pops for this prototype (each argument rounded up to 4) */
	private static int argBytes(FunctionDefinition fd) {
		int n = 0;
		for (ParameterDefinition p : fd.getArguments()) {
			n += (Math.max(p.getLength(), 1) + 3) & ~3;
		}
		return n;
	}

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

// Pre-script: turn on the slower analyzers that matter for a Watcom binary
// with no symbols, before headless auto-analysis runs.
//@category RetroKit
import ghidra.app.script.GhidraScript;

public class EnableDeepAnalysis extends GhidraScript {
	@Override
	protected void run() throws Exception {
		// Finds code in gaps the reference-driven disassembler misses
		setAnalysisOption(currentProgram, "Aggressive Instruction Finder", "true");
		// Recover parameters/return types by running the decompiler per function
		setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");
		setAnalysisOption(currentProgram, "Decompiler Parameter ID.Analysis Decompiler Timeout (sec)", "120");
		// Create functions for every unreferenced code block that looks like one
		setAnalysisOption(currentProgram, "Function Start Search", "true");
		println("Deep analysis options enabled");
	}
}

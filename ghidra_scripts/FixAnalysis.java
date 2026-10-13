// Manual corrections discovered during review:
//   - clear the bogus "no return" flag on functions (truncates callers)
//   - create functions at known code addresses the analyzers missed
// Usage: -preScript FixAnalysis.java noreturn:11f50 func:21a90 func:38650 ...
//@category RetroKit
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

public class FixAnalysis extends GhidraScript {
	@Override
	protected void run() throws Exception {
		for (String arg : getScriptArgs()) {
			String[] kv = arg.split(":");
			Address a = toAddr(Long.parseLong(kv[1], 16));
			if (kv[0].equals("noreturn")) {
				Function f = getFunctionAt(a);
				if (f == null) {
					println("no function at " + a);
					continue;
				}
				f.setNoReturn(false);
				println("cleared noreturn on " + f.getName());
			}
			else if (kv[0].equals("func")) {
				if (getFunctionAt(a) != null) {
					println("function already exists at " + a);
					continue;
				}
				if (getInstructionAt(a) == null) {
					new DisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
				}
				boolean ok = new CreateFunctionCmd(null, a, null, SourceType.USER_DEFINED).applyTo(currentProgram, monitor);
				println("create function at " + a + ": " + ok);
			}
		}
	}
}

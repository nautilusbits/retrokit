# Security

retro-kit runs Ghidra headless on executables you give it, compiles a Ghidra extension
locally (`retrokit install-loader`) and, with `retrokit mcp`, lets an MCP client read an
analysis and write to its `notes/` directory. Please report anything that lets a crafted
executable, data file or workspace run code, write outside the workspace, or make the MCP
server do more than documented.

Report privately through GitHub: the repository's **Security** tab -> **Report a
vulnerability**. Please do not open a public issue for it, and do not attach game files;
a small reproducer (or a description of the crafted input) is enough.

Only the latest release is supported.

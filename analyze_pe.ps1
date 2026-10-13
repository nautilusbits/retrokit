# Headless Ghidra pipeline for Win32 PE executables (MSVC-era games).
#
#   pwsh .\analyze_pe.ps1 -Exe ..\GAME.EXE                          # output ..\game_analysis
#   pwsh .\analyze_pe.ps1 -Ghidra <ghidra> -Exe <dir>\GAME.EXE -Out <out>
#   pwsh .\analyze_pe.ps1 ... -SkipImport            # re-export from an existing project
#   pwsh .\analyze_pe.ps1 ... -Entries <file>        # create functions at the listed addresses (one hex
#                                                    #   per line, tools\find_entries.py), then re-analyse
#   pwsh .\analyze_pe.ps1 ... -Names <dir|csv>       # apply names_*.csv proposals (addr,name,confidence,comment)
#   pwsh .\analyze_pe.ps1 ... -NoExport              # stop after import / entries
#
# Defaults: -Ghidra = $env:GHIDRA_INSTALL_DIR, else first of <kit>\..\ghidra, <kit>\ghidra
#                     containing support\analyzeHeadless.bat;
#           -Out    = <exe dir>\<exe name>_analysis;  -CName = <exe name>_decompiled.c
#
# Output in <Out>\decomp:
#   <exe>_decompiled.c  decompiled C of every function (grep-able)
#   functions.csv       addr,name,size,callers,callees,cc,signature
#   calls.txt           caller -> callee edges;  strings.txt; data_symbols.txt; memory_blocks.txt
#   imports.txt         LIB  name  IAT-slot(s)
param(
    [string]$Ghidra,
    [Parameter(Mandatory)] [string]$Exe,
    [string]$Out,
    [string]$CName,
    [string]$Names,
    [string]$Entries,
    [switch]$SkipImport,
    [switch]$NoExport
)
$ErrorActionPreference = "Stop"
$kit = $PSScriptRoot
if (-not $Ghidra -and $env:GHIDRA_INSTALL_DIR) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $Ghidra) {
    $Ghidra = @("..\ghidra", "ghidra") | ForEach-Object { Join-Path $kit $_ } |
        Where-Object { Test-Path (Join-Path $_ "support\analyzeHeadless.bat") } | Select-Object -First 1
    if (-not $Ghidra) { throw "Ghidra not found: pass -Ghidra or set GHIDRA_INSTALL_DIR" }
}
$Ghidra = (Resolve-Path $Ghidra).Path
$Exe = (Resolve-Path $Exe).Path
$exeBase = [IO.Path]::GetFileNameWithoutExtension($Exe).ToLower()
if (-not $Out) { $Out = Join-Path (Split-Path $Exe) "$($exeBase)_analysis" }
if (-not $CName) { $CName = "$($exeBase)_decompiled.c" }
$headless = Join-Path $Ghidra "support\analyzeHeadless.bat"
if (-not (Test-Path $headless)) { throw "analyzeHeadless.bat not found under $Ghidra" }
# Ghidra rejects project paths with "." or ".." elements: resolve before use.
New-Item -ItemType Directory -Force $Out | Out-Null
$Out = (Resolve-Path $Out).Path
$proj = Join-Path $Out "ghidra_project"
$decomp = Join-Path $Out "decomp"
$logs = Join-Path $Out "logs"
New-Item -ItemType Directory -Force $proj, $decomp, $logs | Out-Null
$name = [IO.Path]::GetFileName($Exe)
$scripts = Join-Path $kit "ghidra_scripts"
Write-Host "Ghidra: $Ghidra"
Write-Host "EXE:    $Exe"
Write-Host "Out:    $Out"

if (-not $SkipImport) {
    Get-ChildItem $proj -Filter "*.lock*" -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Host "== import + auto-analysis (PE loader, default analyzers)"
    & $headless $proj Game -import $Exe -overwrite -log (Join-Path $logs "import.log") 2>&1 |
        Out-File (Join-Path $logs "import_stdout.log")
}
if ($Entries) {
    Write-Host "== create functions at entries + re-analysis"
    & $headless $proj Game -process $name -scriptPath $scripts `
        -preScript CreateFunctionsAtEntries.java ("@" + (Resolve-Path $Entries).Path) `
        -log (Join-Path $logs "entries.log") 2>&1 | Out-File (Join-Path $logs "entries_stdout.log")
    Get-Content (Join-Path $logs "entries.log") | Select-String -Pattern 'Entries:|ERROR' | ForEach-Object Line
}
if ($NoExport) { exit 0 }
Write-Host "== export"
$namesScript = if ($Names) { @("-postScript", "ApplyNames.java", (Resolve-Path $Names).Path) } else { @() }
& $headless $proj Game -process $name -noanalysis -scriptPath $scripts `
    @namesScript `
    -postScript ExportDecompiled.java $decomp $CName `
    -postScript DumpImports.java (Join-Path $decomp "imports.txt") `
    -log (Join-Path $logs "export.log") 2>&1 | Out-File (Join-Path $logs "export_stdout.log")

Get-Content (Join-Path $logs "export.log") | Select-String -Pattern 'Exporting|Export done|DumpImports|ApplyNames:|ERROR' |
    ForEach-Object Line
$rows = Import-Csv (Join-Path $decomp "functions.csv")
Write-Host ("functions: {0}, decompiled C: {1:N0} bytes" -f $rows.Count, (Get-Item (Join-Path $decomp $CName)).Length)
Write-Host "output: $decomp"

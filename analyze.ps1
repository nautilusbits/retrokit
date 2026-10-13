# Headless Ghidra pipeline for DOS/4GW (LE) games built with Watcom C.
#
#   pwsh .\analyze.ps1 -Exe ..\GAME.EXE                                 # Ghidra from ..\ghidra, output ..\game_analysis
#   pwsh .\analyze.ps1 -Ghidra <ghidra> -Exe <dir>\GAME.EXE -Out <out>
#   pwsh .\analyze.ps1 ... -Cspec watcom           # (default) stack-based Watcom (-3s/-5s)
#   pwsh .\analyze.ps1 ... -Cspec watcomreg        # register-based Watcom (-3r/-5r)
#                                                  #   (python tools\detect_cc.py GAME.EXE tells which one)
#   pwsh .\analyze.ps1 ... -Loader LeLoader        # default; use LxLoader for OS/2 LX, VxDLoader for VxD
#   pwsh .\analyze.ps1 ... -SkipImport             # re-run fixup pass + export on an existing project
#   pwsh .\analyze.ps1 ... -Names <dir|csv>        # apply names_*.csv proposals (addr,name,confidence,comment)
#                                                  #   before export, e.g. -SkipImport -Names ..\game_analysis\notes
#   pwsh .\analyze.ps1 ... -Prototypes             # recover prototypes bottom-up before export
#                                                  #   (always on for -Cspec watcomreg)
#
# Defaults: -Ghidra = $env:GHIDRA_INSTALL_DIR, else first of <kit>\..\ghidra, <kit>\ghidra
#                     containing support\analyzeHeadless.bat;
#           -Out    = <exe dir>\<exe name>_analysis;  -CName = <exe name>_decompiled.c
#
# Steps: import + auto-analysis -> functions from LE fixup targets (pointer
# tables) -> re-analysis -> export decompiled C / function index / strings /
# call graph / fixup dump / memory blocks into <Out>\decomp.
param(
    [string]$Ghidra,
    [Parameter(Mandatory)] [string]$Exe,
    [string]$Out,
    [string]$Cspec = "watcom",
    [string]$Loader = "LeLoader",
    [string]$Processor = "x86:LE:32:default",
    [string]$CName,
    [switch]$Prototypes,
    [string]$Names,
    [switch]$SkipImport
)
$ErrorActionPreference = "Stop"
$kit = $PSScriptRoot
if (-not $Ghidra -and $env:GHIDRA_INSTALL_DIR) { $Ghidra = $env:GHIDRA_INSTALL_DIR }
if (-not $Ghidra) {
    $Ghidra = @("..\ghidra", "ghidra") | ForEach-Object { Join-Path $kit $_ } |
        Where-Object { Test-Path (Join-Path $_ "support\analyzeHeadless.bat") } | Select-Object -First 1
    if (-not $Ghidra) { throw "Ghidra not found next to the kit; pass -Ghidra" }
}
$Ghidra = (Resolve-Path $Ghidra).Path
$Exe = (Resolve-Path $Exe).Path
$exeBase = [IO.Path]::GetFileNameWithoutExtension($Exe).ToLower()
if (-not $Out) { $Out = Join-Path (Split-Path $Exe) "$($exeBase)_analysis" }
if (-not $CName) { $CName = "$($exeBase)_decompiled.c" }
$headless = Join-Path $Ghidra "support\analyzeHeadless.bat"
if (-not (Test-Path $headless)) { throw "analyzeHeadless.bat not found under $Ghidra" }
$proj = Join-Path $Out "ghidra_project"
$decomp = Join-Path $Out "decomp"
$logs = Join-Path $Out "logs"
New-Item -ItemType Directory -Force $proj, $decomp, $logs | Out-Null
$Out = (Resolve-Path $Out).Path
$name = [IO.Path]::GetFileName($Exe)
$scripts = Join-Path $kit "ghidra_scripts"
Write-Host "Ghidra: $Ghidra"
Write-Host "EXE:    $Exe  (loader $Loader, cspec $Cspec)"
Write-Host "Out:    $Out"

if (-not $SkipImport) {
    Get-ChildItem $proj -Filter "*.lock*" -ErrorAction SilentlyContinue | Remove-Item -Force
    Write-Host "== import + analysis"
    & $headless $proj Game -import $Exe -loader $Loader -processor $Processor -cspec $Cspec -overwrite `
        -scriptPath $scripts -postScript CreateFunctionsFromFixups.java -log (Join-Path $logs "import.log") 2>&1 |
        Out-File (Join-Path $logs "import_stdout.log")
}
Write-Host "== fixup functions + re-analysis + export"
# Register convention: functions called through the stack (varargs, __cdecl libraries) get __cdecl
$ccScript = if ($Cspec -eq "watcomreg") { @("-preScript", "ApplyStackConvention.java") } else { @() }
# Prototype recovery (callees before callers) removes fake register arguments at call sites
$protoScript = if ($Prototypes -or $Cspec -eq "watcomreg") { @("-postScript", "RecoverPrototypes.java") } else { @() }
$namesScript = if ($Names) { @("-postScript", "ApplyNames.java", (Resolve-Path $Names).Path) } else { @() }
& $headless $proj Game -process $name -scriptPath $scripts `
    -preScript FixTruncatedCallers.java `
    -preScript CreateFunctionsFromFixups.java `
    -preScript MarkStringsConstant.java `
    @ccScript `
    @protoScript `
    @namesScript `
    -postScript ExportDecompiled.java $decomp $CName `
    -postScript DumpFixups.java (Join-Path $decomp "fixups.txt") `
    -log (Join-Path $logs "export.log") 2>&1 | Out-File (Join-Path $logs "export_stdout.log")

Get-Content (Join-Path $logs "export.log") | Select-String -Pattern 'Created|Exporting|Export done|Wrote|ERROR|REPORT|ApplyStackConvention:|MarkStringsConstant:|ApplyNames:|Recovering|iteration' |
    ForEach-Object Line
$rows = Import-Csv (Join-Path $decomp "functions.csv")
Write-Host ("functions: {0}, decompiled C: {1:N0} bytes" -f $rows.Count, (Get-Item (Join-Path $decomp $CName)).Length)
Write-Host "output: $decomp"

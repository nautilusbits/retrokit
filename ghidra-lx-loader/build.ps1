# Builds the LX/LE loader extension against a Ghidra install and installs it into
# <ghidra>\Ghidra\Extensions\ghidra-lx-loader, together with the Watcom compiler specs.
# Default Ghidra location: the first of ..\ghidra, ..\..\ghidra (relative to this
# script) that exists, e.g. <game>\ghidra next to <game>\retro-kit.
#
# Requires only a JDK (javac/jar on PATH or in JAVA_HOME) - no Gradle needed.
#
#   pwsh .\build.ps1            # build + install
#   pwsh .\build.ps1 -NoInstall # build only (output in .\build)

param(
    [string]$GhidraDir,
    [switch]$NoInstall
)

$ErrorActionPreference = "Stop"
$root     = $PSScriptRoot
if (-not $GhidraDir) {
    $GhidraDir = @("..\ghidra", "..\..\ghidra") | ForEach-Object { Join-Path $root $_ } |
        Where-Object { Test-Path (Join-Path $_ "Ghidra\application.properties") } | Select-Object -First 1
    if (-not $GhidraDir) { throw "Ghidra not found next to the kit; pass -GhidraDir" }
}
$ghidra   = (Resolve-Path $GhidraDir).Path
$build    = Join-Path $root "build"
$classes  = Join-Path $build "classes"
$extName  = "ghidra-lx-loader"

$props = Get-Content (Join-Path $ghidra "Ghidra\application.properties") -Raw | ConvertFrom-StringData
$ghidraVersion = $props["application.version"]
$javaRelease   = $props["application.java.compiler"]
Write-Host "Ghidra $ghidraVersion (java $javaRelease) at $ghidra"

$javac = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME "bin\javac.exe" } else { "javac" }
$jar   = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME "bin\jar.exe" }   else { "jar" }

# Classpath: every Ghidra module jar + our bundled libs
$cp = @(Get-ChildItem (Join-Path $ghidra "Ghidra\Framework"), (Join-Path $ghidra "Ghidra\Features") -Recurse -Filter *.jar |
        Where-Object { $_.FullName -match '\\lib\\' } | ForEach-Object FullName)
$cp += Get-ChildItem (Join-Path $root "lib") -Filter *.jar | Where-Object { $_.Name -ne "$extName.jar" } | ForEach-Object FullName

if (Test-Path $build) { Remove-Item -Recurse -Force $build }
New-Item -ItemType Directory -Force $classes | Out-Null

$sources = Get-ChildItem (Join-Path $root "src\main\java") -Recurse -Filter *.java | ForEach-Object FullName
$argFile = Join-Path $build "sources.txt"
# javac @argfiles split on whitespace: quote each path and use forward slashes
Set-Content $argFile ($sources | ForEach-Object { '"' + ($_ -replace '\\', '/') + '"' })

Write-Host "Compiling $($sources.Count) sources..."
& $javac --release $javaRelease -encoding UTF-8 -cp ($cp -join ';') -d $classes "@$argFile"
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

# Extension resources (help, images) live in src\main\resources
$resources = Join-Path $root "src\main\resources"
if (Test-Path $resources) { Copy-Item -Recurse -Force (Join-Path $resources "*") $classes }

$jarPath = Join-Path $build "$extName.jar"
& $jar --create --file $jarPath -C $classes .
if ($LASTEXITCODE -ne 0) { throw "jar failed" }

# Assemble the extension directory layout Ghidra expects
$ext = Join-Path $build $extName
New-Item -ItemType Directory -Force (Join-Path $ext "lib") | Out-Null
Copy-Item $jarPath (Join-Path $ext "lib")
Get-ChildItem (Join-Path $root "lib") -Filter *.jar | Where-Object { $_.Name -notmatch "^$extName" } |
    Copy-Item -Destination (Join-Path $ext "lib")
Copy-Item (Join-Path $root "Module.manifest") $ext
Copy-Item (Join-Path $root "LICENSE") $ext
Copy-Item (Join-Path $root "README.md") $ext
Copy-Item -Recurse -Force (Join-Path $root "ghidra_scripts") $ext
Copy-Item -Recurse -Force (Join-Path $root "data") $ext
(Get-Content (Join-Path $root "extension.properties")) -replace '^version=.*', "version=$ghidraVersion" |
    Set-Content (Join-Path $ext "extension.properties")

Write-Host "Built $ext"

if (-not $NoInstall) {
    $target = Join-Path $ghidra "Ghidra\Extensions\$extName"
    if (Test-Path $target) { Remove-Item -Recurse -Force $target }
    Copy-Item -Recurse $ext $target
    Write-Host "Installed to $target"

    # Stock Ghidra has no Watcom compiler spec, but the loader offers one for
    # DOS/4GW binaries. Drop ours next to the x86 language files and register
    # them in x86.ldefs (idempotent):
    #   watcom    = x86watcom.cspec      stack convention default (-3s/-5s)
    #   watcomreg = x86watcom_reg.cspec  register convention default (-3r/-5r)
    $langDir = Join-Path $ghidra "Ghidra\Processors\x86\data\languages"
    $ldefs = Join-Path $langDir "x86.ldefs"
    $xml = Get-Content $ldefs -Raw
    $marker = '    <compiler name="Borland C++" spec="x86borland.cspec" id="borlandcpp"/>'
    $specs = @(
        @{ File = "x86watcom.cspec";     Id = "watcom";    Name = "Watcom C" },
        @{ File = "x86watcom_reg.cspec"; Id = "watcomreg"; Name = "Watcom C (register)" }
    )
    foreach ($spec in $specs) {
        Copy-Item (Join-Path $root "data\languages\$($spec.File)") $langDir -Force
        if ($xml -notmatch "id=`"$($spec.Id)`"") {
            $idx = $xml.IndexOf($marker)
            if ($idx -lt 0) { throw "Could not find the Borland entry of x86:LE:32:default in $ldefs" }
            $entry = "    <compiler name=`"$($spec.Name)`" spec=`"$($spec.File)`" id=`"$($spec.Id)`"/>"
            $xml = $xml.Insert($idx + $marker.Length, "`r`n$entry")
            Write-Host "Registered $($spec.Id) compiler spec in $ldefs"
        } else {
            Write-Host "$($spec.Id) compiler spec already registered in $ldefs"
        }
    }
    Set-Content $ldefs $xml -NoNewline
}

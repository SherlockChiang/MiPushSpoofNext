param(
    [string]$NdkPath = $env:ANDROID_NDK_HOME,
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

if (-not $NdkPath) {
    $sdkNdk = Join-Path $env:LOCALAPPDATA "Android\Sdk\ndk"
    if (Test-Path -LiteralPath $sdkNdk) {
        $NdkPath = Get-ChildItem -LiteralPath $sdkNdk -Directory |
            Sort-Object Name -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
}

if (-not $NdkPath -or -not (Test-Path -LiteralPath (Join-Path $NdkPath "ndk-build.cmd"))) {
    throw "Android NDK not found. Pass -NdkPath or set ANDROID_NDK_HOME."
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) { $Python = Get-Command py -ErrorAction Stop }

& $Python.Source (Join-Path $Root "scripts\lint_project.py") $Root
if ($LASTEXITCODE -ne 0) { throw "Project validation failed." }
if (-not $SkipTests) {
    & $Python.Source -m unittest discover -s (Join-Path $Root "tests") -p "test_*.py" -v
    if ($LASTEXITCODE -ne 0) { throw "Unit tests failed." }
}

$VersionLines = @(Get-Content -LiteralPath (Join-Path $Root "module\module.prop") |
    Where-Object { $_ -match '^version=' } |
    ForEach-Object { $_.Substring(8) })
if ($VersionLines.Count -ne 1 -or $VersionLines[0] -notmatch '^[A-Za-z0-9._+-]+$') {
    throw "module.prop must contain exactly one safe version value."
}
$Version = $VersionLines[0]
$Native = Join-Path $Root "native"
$Out = Join-Path $Root "out"
$Work = Join-Path $Root ("build\package-" + [Guid]::NewGuid().ToString("N"))
$Stage = Join-Path $Work "module"
$NativeObj = Join-Path $Work "obj"
$NativeLibs = Join-Path $Work "libs"
$TemporaryZip = Join-Path $Work "MiPushSpoofNext-$Version.zip"
$TemporarySourceZip = Join-Path $Work "MiPushSpoofNext-$Version-source.zip"
$Zip = Join-Path $Out "MiPushSpoofNext-$Version.zip"
$SourceZip = Join-Path $Out "MiPushSpoofNext-$Version-source.zip"

try {
    New-Item -ItemType Directory -Force -Path $Stage, (Join-Path $Stage "zygisk"), $Out | Out-Null
    & (Join-Path $NdkPath "ndk-build.cmd") -C $Native `
        "NDK_PROJECT_PATH=." `
        "APP_BUILD_SCRIPT=jni/Android.mk" `
        "NDK_APPLICATION_MK=jni/Application.mk" `
        "NDK_OUT=$NativeObj" `
        "NDK_LIBS_OUT=$NativeLibs"
    if ($LASTEXITCODE -ne 0) { throw "ndk-build failed." }

    Get-ChildItem -LiteralPath (Join-Path $Root "module") -Force |
        Copy-Item -Destination $Stage -Recurse -Force
    $AbiMap = @{
        "armeabi-v7a" = "armeabi-v7a.so"
        "arm64-v8a"   = "arm64-v8a.so"
        "x86"         = "x86.so"
        "x86_64"      = "x86_64.so"
    }
    foreach ($abi in $AbiMap.Keys) {
        $source = Join-Path $NativeLibs "$abi\libmipushspoofnext.so"
        if (-not (Test-Path -LiteralPath $source)) { throw "Missing native output: $source" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $Stage "zygisk\$($AbiMap[$abi])")
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $Stage,
        $TemporaryZip,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false
    )
    $LlvmPrebuilt = Get-ChildItem -LiteralPath (Join-Path $NdkPath "toolchains\llvm\prebuilt") -Directory |
        Select-Object -First 1
    if (-not $LlvmPrebuilt) { throw "LLVM prebuilt directory not found in NDK." }
    $LlvmBin = Join-Path $LlvmPrebuilt.FullName "bin"
    & $Python.Source (Join-Path $Root "scripts\verify_zip.py") $TemporaryZip `
        --module-dir (Join-Path $Root "module") `
        --native-libs-dir $NativeLibs `
        --llvm-bin $LlvmBin
    if ($LASTEXITCODE -ne 0) { throw "ZIP verification failed." }

    & $Python.Source (Join-Path $Root "scripts\package_source.py") $Root $TemporarySourceZip
    if ($LASTEXITCODE -ne 0) { throw "Source ZIP packaging failed." }

    # Use provider-compatible moves so the release script also works on the
    # Windows PowerShell 5.1/.NET Framework that ships with older build hosts.
    if (Test-Path -LiteralPath $Zip) { Remove-Item -LiteralPath $Zip -Force }
    if (Test-Path -LiteralPath $SourceZip) { Remove-Item -LiteralPath $SourceZip -Force }
    Move-Item -LiteralPath $TemporaryZip -Destination $Zip -Force
    Move-Item -LiteralPath $TemporarySourceZip -Destination $SourceZip -Force
    Write-Host "Built: $Zip"
    Write-Host "Built: $SourceZip"
} finally {
    if (Test-Path -LiteralPath $Work) {
        Remove-Item -LiteralPath $Work -Recurse -Force
    }
}

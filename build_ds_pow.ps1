# Build the native DeepSeekHashV1 kernel (lib/ds_pow.dll).
#   powershell -ExecutionPolicy Bypass -File build_ds_pow.ps1
#
# Only needs to be re-run after editing lib/ds_pow.c.
# The solver falls back to the numpy engine when the DLL is absent.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$libDir = Join-Path $here 'lib'

# locate vcvars64.bat (VS 2019/2022/2026, Build Tools, any edition)
$candidates = @(
    "$env:ProgramFiles\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat",
    "$env:ProgramFiles\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat",
    "$env:ProgramFiles\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat",
    "$env:ProgramFiles\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat",
    "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)
$vcvars = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vcvars) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($vsPath) { $vcvars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat' }
    }
}
if (-not $vcvars -or -not (Test-Path $vcvars)) {
    Write-Error "vcvars64.bat not found. Install Visual Studio Build Tools with the C++ workload."
}

Write-Host "using: $vcvars"

# cl.exe cannot overwrite a DLL that a running gateway has loaded
$dllPath = Join-Path $libDir 'ds_pow.dll'
if (Test-Path $dllPath) {
    try {
        $fs = [IO.File]::Open($dllPath, 'Open', 'ReadWrite', 'None')
        $fs.Close()
    } catch {
        Write-Error "lib\ds_pow.dll is locked - a demo_server.py (or python) process has it loaded.`n  Stop it first:  Get-NetTCPConnection -LocalPort 8933 -State Listen | ForEach-Object { Stop-Process -Id `$_.OwningProcess -Force }"
    }
}
Push-Location $libDir
try {
    cmd /c "`"$vcvars`" >nul 2>&1 && cl /nologo /O2 /LD ds_pow.c /Fe:ds_pow.dll /Fo:ds_pow.obj"
    if ($LASTEXITCODE -ne 0) { throw "cl.exe failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
    Remove-Item (Join-Path $libDir '*.obj'), (Join-Path $libDir '*.exp'), (Join-Path $libDir '*.lib') -ErrorAction SilentlyContinue
}

# self-check: SHA3-256 equivalence + known-answer test
Write-Host "running self-check..."
Push-Location $libDir
try {
    python verify_perm.py
    python -c @"
import sys, time; sys.path.insert(0, r'$libDir')
import ds_pow_c, ds_pow
base = b'60abb4757fbda6dc5b8b_1793283137643_'
assert all(ds_pow_c.digest(base, i) == ds_pow.dshash(base + str(i).encode()) for i in (0, 10, 4159, 99999)), 'digest mismatch'
n = ds_pow_c.solve_range(bytes.fromhex('e4d05f8eaf31bea91fac6a8ec62eb7dcca9589467be1b9d12c6f1b83b27a5253'),
                         b'cace58a80ae0889759d5_1793283450015_', 0, 160000)
assert n == 109478, f'KAT failed: {n}'
print('self-check OK (digest match + known answer 109478)')
"@
} finally { Pop-Location }

Write-Host "`nbuilt: $libDir\ds_pow.dll" -ForegroundColor Green

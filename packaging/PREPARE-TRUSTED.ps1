# Apply audited, fail-closed security patches to the PINNED iPASide source.
# Does not change the git commit: patches are local modifications during build.
# IMPORTANT: normalize both upstream AND here-string line endings. On Windows,
# PowerShell source here-strings may be CRLF even when upstream is converted to LF.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$upstream = Join-Path $root '.upstream\ipaside'
$main = Join-Path $upstream 'src\iPASide.Engine\ipaside_engine\__main__.py'
$sign = Join-Path $upstream 'src\iPASide.Engine\ipaside_engine\signing.py'
$build = Join-Path $upstream 'tools\zsign\build-zsign.sh'
foreach ($path in @($main, $sign, $build)) {
    if (-not (Test-Path $path)) { throw "Missing pinned upstream file: $path" }
}

function ConvertTo-LF {
    param([string] $Value)
    return $Value.Replace("`r`n", "`n").Replace("`r", "`n")
}

function Replace-Required {
    param(
        [string] $Source,
        [string] $Expected,
        [string] $Replacement,
        [string] $GuardName
    )
    $sourceLF = ConvertTo-LF $Source
    $expectedLF = ConvertTo-LF $Expected
    $replacementLF = ConvertTo-LF $Replacement
    # Require exactly ONE literal match: mismatched upstream stays fail-closed.
    $matchCount = [regex]::Matches($sourceLF, [regex]::Escape($expectedLF)).Count
    if ($matchCount -ne 1) {
        throw "SECURITY STOP: $GuardName (expected one exact match, found $matchCount). Verify pinned upstream commit; do not bypass this guard."
    }
    return $sourceLF.Replace($expectedLF, $replacementLF)
}

function Write-Utf8NoBom {
    param([string] $Path, [string] $Value)
    [System.IO.File]::WriteAllText($Path, (ConvertTo-LF $Value), (New-Object System.Text.UTF8Encoding($false)))
}

# 1. Protect the 2FA one-time code: read it from a process environment variable,
#    not --code on the Windows process command line.
$t = ConvertTo-LF ([System.IO.File]::ReadAllText($main))
$old = @'
        if args.code:
            result = gsa.complete_2fa(email, password, args.code)
        else:
            result = gsa.begin_login(email, password)
'@
$new = @'
        studio_otp = os.environ.pop("IPASTUDIO_2FA_CODE", "") or args.code
        if studio_otp:
            result = gsa.complete_2fa(email, password, studio_otp)
        else:
            result = gsa.begin_login(email, password)
'@
$t = Replace-Required $t $old $new 'pinned engine 2FA entry point changed'

# Keep Apple email out of process arguments too (the password is already passed
# through IPASIDE_APPLE_PASSWORD by the parent application).
$t = Replace-Required $t '    email = args.email' '    email = os.environ.pop("IPASTUDIO_APPLE_EMAIL", "") or args.email' 'pinned engine login email reader changed'
Write-Utf8NoBom $main $t

# 2. The signed IPA must never pass the P12 password through -p <secret>.
$t = ConvertTo-LF ([System.IO.File]::ReadAllText($sign))
$t = Replace-Required $t '        "-p", p12_password,' '        "-p", "@stdin",' 'pinned engine zsign password argument changed'
$t = Replace-Required $t '    proc = subprocess.run(cmd, capture_output=True, text=True)' '    proc = subprocess.run(cmd, capture_output=True, text=True, input=p12_password + "\n")' 'pinned engine zsign execution changed'
Write-Utf8NoBom $sign $t

# 3. Pin the exact zsign source and apply the password-via-stdin patch.
$t = ConvertTo-LF ([System.IO.File]::ReadAllText($build))
$old = 'git clone --depth 1 https://github.com/zhlynn/zsign.git "$WORK"'
$new = @'
git init "$WORK"
git -C "$WORK" remote add origin https://github.com/zhlynn/zsign.git
# Prevent Git for Windows from converting the pinned zsign C++ source to CRLF.
git -C "$WORK" config core.autocrlf false
git -C "$WORK" fetch --depth 1 origin 9299685bab7ef99827e06e5dfda93af747386590
git -C "$WORK" checkout --detach FETCH_HEAD
test "$(git -C "$WORK" rev-parse HEAD)" = "9299685bab7ef99827e06e5dfda93af747386590"
'@
$t = Replace-Required $t $old $new 'pinned zsign fetch command changed'
$old = 'git apply "$HERE/win-largefile.patch"'
$new = @'
git apply "$HERE/win-largefile.patch"
STUDIO_ROOT="$(cd "$HERE/../../../.." && pwd)"
# Git for Windows / MSYS2 may still deliver CRLF in the worktree.
# Normalize only this verified source file before the LF-based security patch.
sed -i 's/\r$//' src/zsign.cpp
# Git for Windows may also convert our checked-out .patch file to CRLF.
# git apply needs patch/source line endings to match; normalize BOTH to LF.
sed -i 's/\r$//' "$STUDIO_ROOT/packaging/zsign-stdin.patch"
if ! git apply --check "$STUDIO_ROOT/packaging/zsign-stdin.patch"; then
  echo 'SECURITY STOP: zsign stdin patch does not match PINNED source.' >&2
  exit 1
fi
git apply "$STUDIO_ROOT/packaging/zsign-stdin.patch"
'@
$t = Replace-Required $t $old $new 'pinned zsign patch hook changed'
Write-Utf8NoBom $build $t

# 4. Verify the rewritten files before building, without exposing secrets.
$verifyMain = [System.IO.File]::ReadAllText($main)
$verifySign = [System.IO.File]::ReadAllText($sign)
$verifyBuild = [System.IO.File]::ReadAllText($build)
if (-not $verifyMain.Contains('IPASTUDIO_2FA_CODE') -or
    -not $verifyMain.Contains('IPASTUDIO_APPLE_EMAIL') -or
    -not $verifySign.Contains('"@stdin"') -or
    -not $verifySign.Contains('input=p12_password') -or
    -not $verifyBuild.Contains('zsign-stdin.patch')) {
    throw 'SECURITY STOP: patched signing and authentication source could not be verified'
}
Write-Host 'OK: Pinned iPASide security patches applied with CRLF/LF safe exact-match checks.'

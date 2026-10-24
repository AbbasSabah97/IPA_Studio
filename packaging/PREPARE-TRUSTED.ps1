# Apply audited, fail-closed security patches to the PINNED iPASide source.
# Does not change the git commit: patches are local modifications during build.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$upstream=Join-Path $root '.upstream\ipaside'
$main=Join-Path $upstream 'src\iPASide.Engine\ipaside_engine\__main__.py'
$sign=Join-Path $upstream 'src\iPASide.Engine\ipaside_engine\signing.py'
$build=Join-Path $upstream 'tools\zsign\build-zsign.sh'
foreach($path in @($main,$sign,$build)){if(-not(Test-Path $path)){throw "Missing upstream file: $path"}}
# The iPASide CLI normally requires --code <2FA>, which leaks the OTP through
# Windows process creation metadata. Patch to use an environment variable.
$t=[System.IO.File]::ReadAllText($main).Replace("`r`n","`n")
# replace exact multi-line block, fail on upstream changes
$old=@'
        if args.code:
            result = gsa.complete_2fa(email, password, args.code)
        else:
            result = gsa.begin_login(email, password)
'@
$new=@'
        studio_otp = os.environ.pop("IPASTUDIO_2FA_CODE", "") or args.code
        if studio_otp:
            result = gsa.complete_2fa(email, password, studio_otp)
        else:
            result = gsa.begin_login(email, password)
'@
if(-not $t.Contains($old)){throw 'SECURITY STOP: pinned engine 2FA entry point changed'}
$t=$t.Replace($old,$new)
# Keep the email out of process arguments in addition to the password and OTP.
$old='    email = args.email'
$new='    email = os.environ.pop("IPASTUDIO_APPLE_EMAIL", "") or args.email'
if(-not $t.Contains($old)){throw 'SECURITY STOP: pinned engine login email reader changed'}
$t=$t.Replace($old,$new)
[System.IO.File]::WriteAllText($main,$t,(New-Object System.Text.UTF8Encoding($false)))
# zsign is patched to read the P12 password via stdin rather than argv.
$t=[System.IO.File]::ReadAllText($sign).Replace("`r`n","`n")
$old='        "-p", p12_password,'
if(-not $t.Contains($old)){throw 'SECURITY STOP: pinned engine zsign password argument changed'}
$t=$t.Replace($old,'        "-p", "@stdin",')
$old='    proc = subprocess.run(cmd, capture_output=True, text=True)'
if(-not $t.Contains($old)){throw 'SECURITY STOP: pinned engine zsign execution changed'}
$t=$t.Replace($old,'    proc = subprocess.run(cmd, capture_output=True, text=True, input=p12_password + "`n")')
# Python needs a real escaped LF, not PowerShell literal backtick-n inside quotes.
$t=$t.Replace('p12_password + "`n"','p12_password + "\n"')
[System.IO.File]::WriteAllText($sign,$t,(New-Object System.Text.UTF8Encoding($false)))
# Pin native signing source and apply the stdin secret fix after the iPASide
# compatibility patch, on the same audited commit used by the v3 source.
$t=[System.IO.File]::ReadAllText($build).Replace("`r`n","`n")
$old='git clone --depth 1 https://github.com/zhlynn/zsign.git "$WORK"'
$new=@'
git init "$WORK"
git -C "$WORK" remote add origin https://github.com/zhlynn/zsign.git
git -C "$WORK" fetch --depth 1 origin 9299685bab7ef99827e06e5dfda93af747386590
git -C "$WORK" checkout --detach FETCH_HEAD
test "$(git -C "$WORK" rev-parse HEAD)" = "9299685bab7ef99827e06e5dfda93af747386590"
'@.TrimEnd()
if(-not $t.Contains($old)){throw 'SECURITY STOP: upstream zsign fetch command changed'}
$t=$t.Replace($old,$new)
$old='git apply "$HERE/win-largefile.patch"'
$new=@'
git apply "$HERE/win-largefile.patch"
STUDIO_ROOT="$(cd "$HERE/../../../.." && pwd)"
git apply "$STUDIO_ROOT/packaging/zsign-stdin.patch"
'@.TrimEnd()
if(-not $t.Contains($old)){throw 'SECURITY STOP: upstream zsign build patch hook changed'}
$t=$t.Replace($old,$new)
[System.IO.File]::WriteAllText($build,$t.Replace("`r`n","`n"),(New-Object System.Text.UTF8Encoding($false)))
Write-Host 'Applied pinned upstream security patches (2FA env + P12 stdin).'

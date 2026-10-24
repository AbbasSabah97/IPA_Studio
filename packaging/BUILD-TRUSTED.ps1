# Build a single Windows installer with GUI, bundled iPASide engine,
# pinned, patched zsign, and runtime network restriction policy.
param([string]$Version='4.0.0', [string]$Python='python')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
Set-Location $root
$upstream=Join-Path $root '.upstream\ipaside'
$signer=Join-Path $upstream 'src\iPASide.Engine\ipaside_engine\vendor\zsign.exe'
if(-not(Test-Path $signer)){throw 'Native signer missing - run patched MSYS2 build'}
$helpText=((& $signer -h 2>&1) | Out-String)
if(-not $helpText.Contains('@stdin')){throw 'SECURITY STOP: signer cannot read P12 secrets from stdin'}
Write-Host '1/6 - Install GUI build deps and run Python tests'
& $Python -m pip install -r requirements-ui.txt -r requirements-build.txt
if($LASTEXITCODE -ne 0){throw 'pip failed'}
& $Python -m unittest discover -s tests -v
if($LASTEXITCODE -ne 0){throw 'Tests failed'}
Write-Host '2/6 - Verify pinned engine patches'
$main=Get-Content (Join-Path $upstream 'src\iPASide.Engine\ipaside_engine\__main__.py') -Raw
$sign=Get-Content (Join-Path $upstream 'src\iPASide.Engine\ipaside_engine\signing.py') -Raw
if(-not $main.Contains('IPASTUDIO_APPLE_EMAIL') -or -not $main.Contains('IPASTUDIO_2FA_CODE') -or -not $sign.Contains('"@stdin"') -or -not $sign.Contains('input=p12_password')) {
    throw 'SECURITY STOP: upstream engine was not patched'
}
Write-Host '3/6 - Build portable signing engine (incl. native signer)'
& (Join-Path $upstream 'packaging\build-engine.ps1') -Python $Python
if($LASTEXITCODE -ne 0){throw 'Engine build failed'}
$engine=Join-Path $upstream 'dist\engine\python'
if(-not(Test-Path (Join-Path $engine 'python.exe'))){throw 'Portable engine not generated'}
# Policy must load on every launch of the bundled engine, even when invoked
# outside IPA Studio. Also keep a copy alongside the GUI for source/runtime env.
Copy-Item 'policy\sitecustomize.py' (Join-Path $engine 'Lib\site-packages\sitecustomize.py') -Force
Write-Host '4/6 - Check runtime policy & self-test'
$env:IPASTUDIO_APPROVED_ANISETTE='https://new.ani.sidestore.io'
& (Join-Path $engine 'python.exe') -c 'import socket, sitecustomize; assert socket.getaddrinfo is sitecustomize.guarded_getaddrinfo; exec("try:\n socket.getaddrinfo(\"example.org\",443)\n raise AssertionError(\"not blocked\")\nexcept PermissionError:\n print(\"Outbound DNS blocked\")")'
if($LASTEXITCODE -ne 0){throw 'SECURITY STOP: runtime socket guard ineffective'}
Remove-Item Env:IPASTUDIO_APPROVED_ANISETTE -ErrorAction SilentlyContinue
Write-Host '5/6 - Compile GUI and assemble payload'
Remove-Item publish -Recurse -Force -ErrorAction SilentlyContinue
& $Python -m PyInstaller --noconfirm --clean --onedir --windowed --name IPAStudio `
  --distpath publish --workpath .build\pyinstaller --specpath .build `
  --collect-all arabic_reshaper --collect-all bidi main.py
if($LASTEXITCODE -ne 0){throw 'GUI build failed'}
$dest=Join-Path $root 'publish\IPAStudio'
if(-not(Test-Path (Join-Path $dest 'IPAStudio.exe'))){throw 'Missing GUI EXE'}
New-Item -ItemType Directory (Join-Path $dest 'engine') -Force | Out-Null
Copy-Item $engine (Join-Path $dest 'engine\python') -Recurse -Force
Copy-Item policy (Join-Path $dest 'policy') -Recurse -Force
Copy-Item (Join-Path $upstream 'LICENSE') (Join-Path $dest 'iPASide-LICENSE.txt') -Force
& (Join-Path $dest 'engine\python\python.exe') -m ipaside_engine version
if($LASTEXITCODE -ne 0){throw 'Copied engine failed'}
Write-Host '6/6 - Build setup and checksums'
$iscc=$null
foreach($candidate in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe", "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) {
    if($candidate -and (Test-Path $candidate)){$iscc=$candidate;break}
}
if(-not $iscc){$cmd=Get-Command ISCC.exe -ErrorAction SilentlyContinue; if($cmd){$iscc=$cmd.Source}}
if(-not $iscc){throw 'Inno Setup compiler missing'}
& $iscc "/DAppVersion=$Version" (Join-Path $root 'packaging\IPAStudio.iss')
if($LASTEXITCODE -ne 0){throw 'Inno Setup build failed'}
$file=Join-Path $root "dist\installer\IPAStudio-Trusted-Setup-$Version.exe"
if(-not(Test-Path $file)){throw 'Missing setup EXE'}
$sum=(Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content (Join-Path $root 'dist\installer\SHA256SUMS.txt') "$sum  $(Split-Path $file -Leaf)" -Encoding ascii
& $Python -m pip freeze | Set-Content (Join-Path $root 'dist\installer\build-dependencies.txt')
Write-Host "Built installer: $file"

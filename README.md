# IPA Studio Trusted v4.0 — Free Apple signing via one selected V3 Anisette server

**Source + GitHub Windows installer workflow, not a prebuilt installer. End-to-end iOS 26 installation is not yet tested.**

This Python Windows shell bundles a pinned, locally patched version of the open-source iPASide Engine and source-built zsign to let a user sign in with an ordinary Apple ID, obtain personal-development signing from Apple, sign an IPA locally, and install it over USB. Free signatures/profiles generally expire after 7 days.

## Privacy model

1. The user chooses one server from **SideStore V3** (`https://new.ani.sidestore.io`) or **jkcoxson Mac V3** (`https://mac-ani.jkcoxson.com`), with explicit consent. There is no automatic fallback.
2. The third-party Anisette server can see an IP address, a random provisioning identifier and opaque protocol blobs. Upstream iPASide's V3 design sends **no Apple account email, password, 2FA or session token** to the Anisette server. However, no public server can be guaranteed safe.
3. Apple authentication and provisioning use `gsa.apple.com` and `developerservices2.apple.com` directly, over verified TLS in upstream iPASide.
4. A Python-level `sitecustomize.py` egress guard restricts DNS/socket connections to Apple, the single approved server and local loopback. It is *defense in depth, not an OS firewall, antivirus, or a guarantee about native dependencies or Windows services.* The compiled GUI has no updater/telemetry built into this project.
5. Apple email, password and OTP are passed to the engine using child process environment variables, not CLI args; native zsign is patched to accept its P12 password from stdin. No Apple password is stored in the GUI settings.
6. **Caveat:** iPASide upstream persists Apple session tokens as local JSON in `%LOCALAPPDATA%\iPASide`. These files are not protected with independent DPAPI encryption in the pinned source. Protect the Windows user account and preferably use a separate Apple ID.

## Build

1. Create a private GitHub repo, upload the full source including `.github`.
2. Actions → **Build IPA Studio Trusted v4 (Windows)** → Run workflow.
3. Download artifact `IPAStudio-Trusted-v4-Windows-Setup`, verify its `SHA256SUMS.txt` and run `IPAStudio-Trusted-Setup-4.0.0.exe`.
4. Install Apple's Apple Devices Windows app or equivalent official iPhone USB drivers.

Build fetches the pinned iPASide source at commit `be811fcaea8556fe5108dd25279d626fa0d56435` and a pinned zsign source at commit `9299685bab7ef99827e06e5dfda93af747386590`. The scripts fail closed if patch anchors change. The installer bundles the local Python runtime + source-built signer. Build-time GitHub/PyPI/MSYS2 downloads are distinct from runtime operations.

## Use

In **Privacy & Settings**, choose/consent to the selected V3 server. In **Apple ID**, enter your ordinary Apple credentials and finish 2FA. Plug in and trust the iPhone via USB. On the IPA tab, scan/select a USB iPhone, browse a compatible `.ipa`, click **Sign & Install**. Enable Developer Mode/trust the developer profile on the iPhone as prompted. To renew after ~5–6 days, use **View installed apps → Refresh selected/all**.

No P12 purchase, Mac, paid Apple Developer account or additional iPASide installation is expected after a successful Windows build. Some DRM-encrypted App Store IPAs and apps requiring restricted entitlements will not install. Real-device testing still needed. Build and use only a repo and artifacts you trust.

Run local offline tests: `python -m unittest discover -s tests -v`

Arabic detailed instructions: `README_AR.md`.

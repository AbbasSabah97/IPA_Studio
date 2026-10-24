"""Local IPA analysis, provisioning checks and secure subprocess adapters.

No Apple account credentials are stored or transmitted by IPA Studio itself.
The external iPASide engine handles Apple authentication and device communication.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Any

from .privacy import server_host, selected_url

APP_NAME = "IPA Studio"
MAX_PLIST_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 25000


class StudioError(RuntimeError):
    pass


@dataclass(frozen=True)
class IPAInfo:
    path: Path
    name: str
    bundle_id: str
    version: str
    build: str
    minimum_ios: str
    app_bundle: str
    extensions: int
    watch_apps: int
    size_mb: float
    has_profile: bool


def inspect_ipa(path: str | Path) -> IPAInfo:
    """Read metadata only: never extract or execute untrusted IPA contents."""
    p = Path(path).expanduser()
    if not p.is_file() or p.suffix.lower() != ".ipa":
        raise StudioError("Select an existing file ending in .ipa")
    try:
        with zipfile.ZipFile(p) as z:
            names = z.namelist()
            if len(names) > MAX_MEMBERS:
                raise StudioError("IPA archive has too many entries")
            candidates = [n for n in names if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", n)]
            if len(candidates) != 1:
                raise StudioError("IPA must have one Payload/<app>.app/Info.plist")
            manifest = candidates[0]
            entry = z.getinfo(manifest)
            if entry.file_size > MAX_PLIST_BYTES:
                raise StudioError("Info.plist is unusually large")
            with z.open(entry) as f:
                info = plistlib.loads(f.read(MAX_PLIST_BYTES + 1))
            if not isinstance(info, dict):
                raise StudioError("Invalid Info.plist")
            root = manifest.rsplit("/", 1)[0] + "/"
            bundle_id = str(info.get("CFBundleIdentifier") or "")
            if not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", bundle_id):
                raise StudioError("IPA has no valid CFBundleIdentifier")
            extensions = {n.split(".appex/")[0] for n in names if n.startswith(root + "PlugIns/") and ".appex/" in n}
            watch_apps = {n.split(".app/")[0] for n in names if n.startswith(root + "Watch/") and ".app/" in n}
            return IPAInfo(
                path=p.resolve(),
                name=str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or "Unknown"),
                bundle_id=bundle_id,
                version=str(info.get("CFBundleShortVersionString") or "—"),
                build=str(info.get("CFBundleVersion") or "—"),
                minimum_ios=str(info.get("MinimumOSVersion") or "—"),
                app_bundle=root.rstrip("/"),
                extensions=len(extensions),
                watch_apps=len(watch_apps),
                size_mb=round(p.stat().st_size / 1024**2, 2),
                has_profile=root + "embedded.mobileprovision" in names,
            )
    except (zipfile.BadZipFile, OSError, ValueError, plistlib.InvalidFileException, EOFError) as exc:
        raise StudioError(f"Cannot read IPA: {exc}") from exc


def parse_profile(path: str | Path) -> dict[str, Any]:
    """Inspect CMS-wrapped .mobileprovision without running external tools.

    Apple profiles commonly contain an embedded XML plist. DER only variants
    are not supported here; failure is conservative and does not assert invalidity.
    """
    p = Path(path)
    if not p.is_file():
        raise StudioError("Provisioning profile file not found")
    if p.stat().st_size > 20 * 1024 * 1024:
        raise StudioError("Provisioning profile is unexpectedly large")
    content = p.read_bytes()
    try:
        record = plistlib.loads(content)
    except (ValueError, plistlib.InvalidFileException, TypeError):
        match = re.search(rb"<\?xml\b.*?</plist>", content, re.DOTALL)
        if not match:
            raise StudioError("Cannot decode CMS provisioning profile. Use Apple's tools for verification.")
        try:
            record = plistlib.loads(match.group(0))
        except (ValueError, plistlib.InvalidFileException, TypeError) as exc:
            raise StudioError("Could not parse embedded provisioning profile") from exc
    if not isinstance(record, dict):
        raise StudioError("Profile must be a dictionary")
    ent = record.get("Entitlements") or {}
    expiration = record.get("ExpirationDate")
    if isinstance(expiration, dt.datetime):
        if expiration.tzinfo is None:
            expiration = expiration.replace(tzinfo=dt.timezone.utc)
        else:
            expiration = expiration.astimezone(dt.timezone.utc)
        expiry = expiration.isoformat()
        expired = expiration <= dt.datetime.now(dt.timezone.utc)
    else:
        expiry = "Unknown"
        expired = None
    return {
        "name": str(record.get("Name") or "Unknown"),
        "expiration": expiry,
        "expired": expired,
        "application_identifier": str(ent.get("application-identifier") or ""),
        "devices": list(record.get("ProvisionedDevices") or []),
        "teams": list(record.get("TeamIdentifier") or []),
    }


def profile_matches_bundle(profile: dict[str, Any], bundle_id: str) -> bool | None:
    ident = profile.get("application_identifier", "")
    if not ident or "." not in ident:
        return None
    # TEAMID.com.example.* or TEAMID.com.example.app
    allowed = ident.split(".", 1)[1]
    return allowed == "*" or allowed == bundle_id or (allowed.endswith(".*") and bundle_id.startswith(allowed[:-1]))


def bundled_engine() -> Path | None:
    """Prefer the Windows-installation's private engine; no extra install required.

    In a PyInstaller onedir build, sys.executable points to IPAStudio.exe
    alongside the engine directory. When running source locally, the project's
    root may contain an engine folder built for development.
    """
    roots = []
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    roots.append(Path(__file__).resolve().parent.parent)
    for root in roots:
        candidate = root / "engine" / "python" / "python.exe"
        if candidate.is_file():
            return candidate
    return None


def engine_candidates() -> list[Path]:
    paths: list[Path] = []
    built_in = bundled_engine()
    if built_in:
        paths.append(built_in)
    custom = os.environ.get("IPASTUDIO_ENGINE_PYTHON")
    if custom:
        paths.append(Path(custom))
    local = os.environ.get("LOCALAPPDATA")
    if local:
        paths.extend([
            Path(local) / "Programs" / "iPASide" / "engine" / "python" / "python.exe",
            Path(local) / "iPASide" / "engine" / "python" / "python.exe",
        ])
    paths.extend([
        Path.home() / "AppData" / "Local" / "Programs" / "iPASide" / "engine" / "python" / "python.exe",
    ])
    # Standard python is useful for a user-built copy of the open-source engine.
    # It is not automatically chosen unless the engine module can be imported.
    return paths


def guess_engine() -> str:
    for p in engine_candidates():
        if p.is_file():
            return str(p)
    return ""


def _popen(command: list[str], env: dict[str, str] | None = None,
           logger: Callable[[str], None] | None = None) -> tuple[int, str, str]:
    """Run an argument-list command without shell expansion or command logging."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    output: list[str] = []
    errors: list[str] = []
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, text=True, encoding="utf-8", errors="replace",
                            creationflags=flags)

    def drain(stream, sink, progress=False):
        if stream is None:
            return
        for line in stream:
            if sum(map(len, sink)) < 2_000_000:
                sink.append(line)
            if logger and progress:
                try:
                    ev = json.loads(line)
                    if isinstance(ev, dict) and ev.get("event") == "progress":
                        part = ev.get("step") or ev.get("status") or ev.get("phase") or "Processing"
                        logger(f"{part} · {ev.get('percent', '?')}%")
                    else:
                        logger(line.strip()[:400])
                except json.JSONDecodeError:
                    logger(line.strip()[:400])
        stream.close()

    t1 = threading.Thread(target=drain, args=(proc.stdout, output), daemon=True)
    t2 = threading.Thread(target=drain, args=(proc.stderr, errors, True), daemon=True)
    t1.start(); t2.start()
    exit_code = proc.wait()
    t1.join(); t2.join()
    return exit_code, "".join(output), "".join(errors)


def network_policy_dir() -> Path:
    """The policy is always shipped with the binary and copied beside the engine."""
    roots = [Path(sys.executable).resolve().parent] if getattr(sys, "frozen", False) else []
    roots.append(Path(__file__).resolve().parent.parent)
    for root in roots:
        location = root / "policy"
        if (location / "sitecustomize.py").is_file():
            return location
    raise StudioError("Security policy is missing. Reinstall the complete secure edition.")


def secured_environment(server: str, *, password: str | None = None,
                        code: str | None = None, email: str | None = None) -> dict[str, str]:
    # Do not allow environment overrides to select another Anisette host, use
    # local emulation, switch to Wi-Fi, or force traffic through an HTTP proxy.
    server_host(server)
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy",
                "all_proxy", "IPASIDE_APPLE_PASSWORD", "IPASTUDIO_2FA_CODE", "IPASTUDIO_APPLE_EMAIL"):
        env.pop(key, None)
    env.update({
        "IPASIDE_ANISETTE": "remote",
        "IPASIDE_ANISETTE_SERVER": server,
        "IPASTUDIO_APPROVED_ANISETTE": server,
        "IPASIDE_CONNECTION": "usb",
        "PYTHONPATH": str(network_policy_dir()),
        "PYTHONNOUSERSITE": "1",
        "NO_PROXY": "*",
    })
    if password is not None:
        env["IPASIDE_APPLE_PASSWORD"] = password
    if code is not None:
        env["IPASTUDIO_2FA_CODE"] = code
    if email is not None:
        env["IPASTUDIO_APPLE_EMAIL"] = email
    return env


def run_engine(python_exe: str, cli_args: list[str], *, server: str,
               password: str | None = None, code: str | None = None,
               email: str | None = None, logger: Callable[[str], None] | None = None) -> Any:
    """Use only the local bundled engine and an explicit HTTPS Anisette endpoint.

    The 2FA code and Apple password are sent to the child via environment, NOT
    command line; builder patches the pinned engine to read IPASTUDIO_2FA_CODE.
    """
    if not python_exe or not Path(python_exe).is_file():
        raise StudioError("Signing engine is missing. Reinstall IPA Studio Trusted.")
    selected = Path(python_exe).resolve()
    bundled = bundled_engine()
    if bundled is None or selected != bundled.resolve():
        raise StudioError("Only the bundled, pinned signing engine is allowed")
    env = secured_environment(server, password=password, code=code, email=email)
    # Explicit USB transport, never auto/Wi-Fi fallback.
    if "--connection" in cli_args:
        idx = cli_args.index("--connection")
        if idx + 1 >= len(cli_args) or cli_args[idx + 1] != "usb":
            raise StudioError("Only USB is permitted")
    if "--code" in cli_args or "--creds-file" in cli_args or (cli_args and cli_args[0] == "login" and "--email" in cli_args):
        raise StudioError("Sensitive login credentials cannot be passed on command line")
    command = [str(selected), "-m", "ipaside_engine", *cli_args, "--json"]
    try:
        # Do not echo raw child stderr during login: could include sensitive data.
        safe_logger = None if (cli_args and cli_args[0] == "login") else logger
        returncode, stdout, stderr = _popen(command, env=env, logger=safe_logger)
    except OSError as exc:
        raise StudioError("Could not start signing engine") from exc
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise StudioError("Engine output is not valid JSON; review local diagnostics") from exc
    if returncode != 0 or (isinstance(result, dict) and result.get("status") == "error"):
        # Raw exceptions from upstream might contain tokens. Only show a limited,
        # locally returned error; never add the secret to a debug log.
        reason = result.get("error") if isinstance(result, dict) else None
        message = str(reason or "Engine could not complete the operation")
        for secret in (password, code, email):
            if secret:
                message = message.replace(secret, "[REDACTED]")
        raise StudioError(message[:800])
    return result



def run_ideviceinstaller(exe: str, ipa: str, *, logger=None) -> str:
    if not Path(exe).is_file() or not Path(ipa).is_file():
        raise StudioError("Select a valid ideviceinstaller.exe and signed IPA")
    try:
        code, stdout, stderr = _popen([exe, "install", ipa], logger=logger)
    except OSError as exc:
        raise StudioError(f"Cannot start ideviceinstaller: {exc}") from exc
    if code:
        raise StudioError("Device install failed: " + (stderr or stdout)[-1300:])
    if logger:
        logger("Device installation command completed")
    return stdout[-2000:]


def default_output_path(ipa: str | Path) -> Path:
    src = Path(ipa)
    return Path.home() / "Documents" / "IPA Studio" / "Signed" / f"{src.stem}-signed.ipa"

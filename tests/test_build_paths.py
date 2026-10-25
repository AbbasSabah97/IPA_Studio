"""Prevent regression of the upstream build-engine.ps1 working-directory leak.

The pinned iPASide script calls Set-Location, so the caller must restore
the IPA Studio root and use project-absolute policy/packaging paths.
"""
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "packaging" / "BUILD-TRUSTED.ps1"


class BuildPathsTests(unittest.TestCase):
    def test_project_paths_not_dependent_on_upstream_current_directory(self):
        source = BUILD.read_text(encoding="utf-8")
        # A nested build script can change PowerShell's global current location.
        self.assertIn("Push-Location $root", source)
        self.assertIn("} finally {\n    Pop-Location\n}", source)
        self.assertIn("Set-Location $root", source)
        # Both the engine sitecustomize and the GUI policy copy are rooted.
        self.assertIn("$policyFile=Join-Path $root 'policy\\sitecustomize.py'", source)
        self.assertIn("Copy-Item -LiteralPath $policyFile", source)
        self.assertIn("SECURITY STOP: missing policy file", source)
        self.assertIn("Copy-Item -LiteralPath (Join-Path $root 'policy')", source)
        # PyInstaller and output paths must be independent of the caller's cwd.
        self.assertIn("--distpath (Join-Path $root 'publish')", source)
        self.assertIn("(Join-Path $root 'main.py')", source)

    def test_powershell_build_script_parses(self):
        pwsh = shutil.which("pwsh")
        if pwsh is None:
            self.skipTest("PowerShell unavailable")
        path = str(BUILD).replace("'", "''")
        check = (
            "$tokens=$null; $errors=$null; "
            "[void][System.Management.Automation.Language.Parser]::ParseFile("
            f"'{path}',[ref]$tokens,[ref]$errors); "
            "if($errors.Count){$errors | Out-String | Write-Error; exit 1}"
        )
        proc = subprocess.run([pwsh, "-NoProfile", "-NonInteractive", "-Command", check],
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()

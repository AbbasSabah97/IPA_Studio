"""Regression checks for the pinned zsign stdin-password patch on Windows.

Git for Windows may materialize source/patch files with CRLF. The build
normalizes both to LF before applying the required security patch. Actual
patch compatibility is tested; Git's treatment of *unnormalized* CRLF is
not portable and is deliberately not asserted.
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "packaging" / "zsign-stdin.patch"


def fake_upstream_source() -> list[str]:
    """Minimal source fixture at the *pinned* patch's expected hunk locations."""
    lines = [f"// unchanged upstream filler {i}" for i in range(1, 401)]
    anchors = {
        1: '#include "common.h"',
        2: "#include <list>",
        3: "#include <set>",
        4: '#include "macho.h"',
        130: '\tZLog::Print("-f, --force\\t\\tForce sign without cache when signing folder.\\n");',
        131: '\tZLog::Print("-o, --output\\t\\tPath to output ipa file.\\n");',
        132: '\tZLog::Print("-p, --password\\t\\tPassword for private key or p12 file.\\n");',
        133: '\tZLog::Print("-b, --bundle_id\\t\\tNew bundle id to change.\\n");',
        312: "\tif (optind >= argc) {",
        313: "\t\treturn usage();",
        314: "\t}",
    }
    for line_number, line in anchors.items():
        lines[line_number - 1] = line
    return lines


class WindowsZsignPatchTests(unittest.TestCase):
    def test_windows_build_normalizes_both_files_and_fails_closed(self):
        script = (ROOT / "packaging" / "PREPARE-TRUSTED.ps1").read_text(encoding="utf-8")
        self.assertIn('git -C "$WORK" config core.autocrlf false', script)
        self.assertIn("sed -i 's/\\r$//' src/zsign.cpp", script)
        self.assertIn("sed -i 's/\\r$//' \"$STUDIO_ROOT/packaging/zsign-stdin.patch\"", script)
        self.assertIn('git apply --check "$STUDIO_ROOT/packaging/zsign-stdin.patch"', script)
        self.assertIn("SECURITY STOP: zsign stdin patch", script)
        self.assertIn("packaging/*.patch text eol=lf",
                      (ROOT / ".gitattributes").read_text(encoding="utf-8"))

    def test_normalized_patch_applies_and_modified_source_is_rejected(self):
        if not shutil.which("git"):
            self.skipTest("git is unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=work, check=True)
            cpp = work / "src" / "zsign.cpp"
            cpp.parent.mkdir()
            upstream = fake_upstream_source()
            # Emulate a Windows worktree, followed by the production LF fix.
            cpp.write_bytes(("\r\n".join(upstream) + "\r\n").encode("utf-8"))
            cpp.write_bytes(cpp.read_bytes().replace(b"\r\n", b"\n"))
            self.assertNotIn(b"\r\n", cpp.read_bytes())

            # Emulate a patch checked out as CRLF, followed by LF normalization.
            normalized_patch = work / "stdin-password.patch"
            normalized_patch.write_bytes(
                PATCH.read_bytes().replace(b"\r\n", b"\n")
                                  .replace(b"\n", b"\r\n"))
            normalized_patch.write_bytes(
                normalized_patch.read_bytes().replace(b"\r\n", b"\n"))
            dry_run = subprocess.run(["git", "apply", "--check", str(normalized_patch)],
                                     cwd=work, text=True, capture_output=True)
            self.assertEqual(dry_run.returncode, 0, dry_run.stderr)

            # Security check must reject genuine upstream mismatches.
            cpp.write_text(cpp.read_text(encoding="utf-8").replace(
                '#include "common.h"', '#include "unexpected-upstream.h"', 1),
                encoding="utf-8", newline="\n")
            rejected = subprocess.run(["git", "apply", "--check", str(normalized_patch)],
                                      cwd=work, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0,
                                "A changed upstream source must stop the build")

            # Restore pinned context; apply and check both security edits.
            cpp.write_bytes(("\n".join(upstream) + "\n").encode("utf-8"))
            subprocess.run(["git", "apply", str(normalized_patch)], cwd=work, check=True)
            patched = cpp.read_text(encoding="utf-8")
            self.assertIn("#include <iostream>", patched)
            self.assertIn("std::getline(std::cin, strPassword)", patched)


if __name__ == "__main__":
    unittest.main()

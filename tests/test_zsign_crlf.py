"""Regression: Git for Windows can checkout pinned zsign.cpp with CRLF.

This must fail closed until its line endings are normalized. The stdin
security patch may never be skipped just to obtain a successful build.
"""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

class WindowsZsignPatchTests(unittest.TestCase):
    def test_windows_crlf_is_normalized_without_bypassing_security_patch(self):
        script = (ROOT / "packaging" / "PREPARE-TRUSTED.ps1").read_text(encoding="utf-8")
        self.assertIn('git -C "$WORK" config core.autocrlf false', script)
        self.assertIn("sed -i 's/\\r$//' src/zsign.cpp", script)
        self.assertIn('git apply --check "$STUDIO_ROOT/packaging/zsign-stdin.patch"', script)
        self.assertIn('SECURITY STOP: zsign stdin patch', script)
        self.assertIn('sed -i 's/\r$//' "$STUDIO_ROOT/packaging/zsign-stdin.patch"', script)
        self.assertIn('packaging/*.patch text eol=lf', (ROOT / '.gitattributes').read_text())
        if not shutil.which("git"):
            self.skipTest("git unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            src = root / "src" / "zsign.cpp"
            src.parent.mkdir()
            lines = [f"// filler {i}" for i in range(1, 401)]
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
            for number, value in anchors.items():
                lines[number - 1] = value
            patch = str(ROOT / "packaging" / "zsign-stdin.patch")
            src.write_bytes(("\r\n".join(lines) + "\r\n").encode("utf-8"))
            before = subprocess.run(["git", "apply", "--check", patch],
                                    cwd=root, capture_output=True, text=True)
            self.assertNotEqual(before.returncode, 0, "CRLF should reproduce the original failure")
            self.assertIn("patch failed: src/zsign.cpp:1", before.stderr)
            # Equivalent to GNU sed -i 's/\r$//' on the source file.
            src.write_bytes(src.read_bytes().replace(b"\r\n", b"\n"))
            # Also reproduce the *actual* CI failure: CRLF patch vs LF source.
            patch_crlf = root / "patch-crlf.patch"
            patch_crlf.write_bytes(Path(patch).read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
            bad_patch = subprocess.run(["git", "apply", "--check", str(patch_crlf)],
                                       cwd=root, capture_output=True, text=True)
            self.assertNotEqual(bad_patch.returncode, 0)
            self.assertIn("patch failed: src/zsign.cpp:1", bad_patch.stderr)
            # Normalize the patch as the build now does.
            patch_crlf.write_bytes(patch_crlf.read_bytes().replace(b"\r\n", b"\n"))
            good_patch = subprocess.run(["git", "apply", "--check", str(patch_crlf)],
                                        cwd=root, capture_output=True, text=True)
            self.assertEqual(good_patch.returncode, 0, good_patch.stderr)
            after = subprocess.run(["git", "apply", "--check", patch],
                                   cwd=root, capture_output=True, text=True)
            self.assertEqual(after.returncode, 0, after.stderr)
            subprocess.run(["git", "apply", patch], cwd=root, check=True)
            self.assertIn("std::getline(std::cin, strPassword)", src.read_text())

if __name__ == "__main__":
    unittest.main()

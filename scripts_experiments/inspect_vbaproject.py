"""Extract vbaProject.bin from an OOXML file and list its OLE streams with oledir.
Python version of inspect_vbaproject.ps1.
https://github.com/decalage2/oletools/wiki/oledir
"""
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# Repo root = the folder above this script, so defaults work from any directory
REPO_ROOT = Path(__file__).resolve().parent.parent


def find_vba_project(zf: zipfile.ZipFile) -> str | None:
    # xl/ for Excel, word/ for Word, ppt/ for PowerPoint, so search instead of hardcoding
    for name in zf.namelist():
        if name.lower().endswith("vbaproject.bin"):
            return name
    return None


def run_oledir(doc: Path, out_dir: Path) -> Path:
    with zipfile.ZipFile(doc) as zf:
        member = find_vba_project(zf)
        if member is None:
            sys.exit(f"No vbaProject.bin in {doc} (no macros?)")

        # Temporary folder outside the repo, deleted automatically after the with block
        with tempfile.TemporaryDirectory(prefix="macro-look-") as work:
            zf.extract(member, work)

            # cwd + relative path keep C:\Users\<name>\AppData\... out of the report
            result = subprocess.run(
                [sys.executable, "-m", "oletools.oledir", member],
                cwd=work,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONWARNINGS": "ignore"},
            )

    if result.stderr.strip():
        print(result.stderr, file=sys.stderr)

    out_dir.mkdir(parents=True, exist_ok=True)
    report = out_dir / f"{doc.stem}-oledir.txt"
    report.write_text(result.stdout, encoding="utf-8")
    print(result.stdout)
    return report


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: py inspect_vbaproject.py <file.xlsm> [out_dir]")
    doc = Path(sys.argv[1])
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else REPO_ROOT / "output"
    print(f"Report saved to {run_oledir(doc, out_dir)}")

"""Run olevba on every macro document in a folder 
and save one report per file.
https://github.com/decalage2/oletools/wiki/olevba
"""
import os
import subprocess
import sys
from pathlib import Path

MACRO_EXTENSIONS = {".xlsm", ".docm", ".pptm", ".dotm", ".xls", ".doc"}

# Repo root = the folder above this script, so defaults work from any directory
REPO_ROOT = Path(__file__).resolve().parent.parent


def run_olevba(doc: Path, out_dir: Path) -> Path:
    # sys.executable -m runs the olevba from this venv, on Windows and on Linux CI
    # cwd + bare file name keep absolute paths (D:\..., user names) out of the report
    result = subprocess.run(
        [sys.executable, "-m", "oletools.olevba", doc.name],
        cwd=doc.parent,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        # PYTHONWARNINGS=ignore hides pyparsing deprecation warnings from oletools
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONWARNINGS": "ignore"},
    )
    # olevba exits non-zero when it finds macros, so the exit code is not checked

    # Report gets stdout only; real errors on stderr are shown on screen instead
    if result.stderr.strip():
        print(result.stderr, file=sys.stderr)

    report = out_dir / f"{doc.stem}-olevba.txt"
    report.write_text(result.stdout, encoding="utf-8")
    return report


def main(docs_dir: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # ~$ files are Office lock files created while a document is open, not documents
    docs = sorted(p for p in docs_dir.iterdir()
                  if p.suffix.lower() in MACRO_EXTENSIONS
                  and not p.name.startswith("~$"))
    if not docs:
        sys.exit(f"no macro documents in {docs_dir}")

    for doc in docs:
        print(f"{doc}  ->  {run_olevba(doc, out_dir)}")


if __name__ == "__main__":
    docs_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO_ROOT / "samples" / "documents"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else REPO_ROOT / "output"
    main(docs_dir, out_dir)

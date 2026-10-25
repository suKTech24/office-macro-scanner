"""Show that an .xlsm is a ZIP and locate its VBA project.
https://docs.python.org/3/library/zipfile.html
ooxml - Office Open XML
"""
import sys
import zipfile
from pathlib import Path


def main(path: Path) -> None:
    print(f"is ZIP: {zipfile.is_zipfile(path)}")

    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            print(f"{info.file_size:>10}  {info.filename}")

        content_types = zf.read("[Content_Types].xml").decode("utf-8")
        print("\nvbaProject declared in [Content_Types].xml:",
              "vbaProject" in content_types)

        if "xl/vbaProject.bin" in zf.namelist():
            vba = zf.read("xl/vbaProject.bin")
            print(f"xl/vbaProject.bin size: {len(vba)} bytes")
            print("'PriceIncludingGst' found as plain bytes:",
                  b"PriceIncludingGst" in vba)


if __name__ == "__main__":
    main(Path(sys.argv[1]))

import sys 
import zipfile
from pathlib import Path

def main(path: Path) -> None:
    print(f"is ZIP: {zipfile.is_zipfile(path)}")

    with zipfile.ZipExtFile(path) as zf:
        for info in zf.infolist():
            print(f"{info.file_size:>10}  {info.filename}")
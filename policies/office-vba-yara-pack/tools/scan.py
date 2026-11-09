#!/usr/bin/env python3
"""Scan extracted Office artifacts with the rules for their input kind."""

import argparse
import json
from pathlib import Path
import stat
import sys

import yara


RULE_ROOT = Path(__file__).resolve().parents[1] / "rules"
KINDS = ("vba", "pcode", "xlm", "office_xml", "payload", "parser_evidence")
MAX_BYTES = 16 * 1024 * 1024
TIMEOUT_SECONDS = 10
MAX_LOCATIONS = 5
EVIDENCE_FLAGS = frozenset({
    b"VBA_STOMPING_SUSPECTED",
    b"VBA_PCODE_WITH_EMPTY_SOURCE",
    b"VBA_ANALYSIS_INCOMPLETE",
})


def compile_kind(kind):
    files = sorted((RULE_ROOT / kind).rglob("*.yar"))
    if not files:
        raise ValueError(f"no rule files for artifact kind {kind}")
    return yara.compile(
        sources={kind: "\n".join(path.read_text(encoding="utf-8") for path in files)},
        error_on_warning=True,
        includes=False,
    )


def read_artifact(path, kind):
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("input must be a regular file")
    if info.st_size > MAX_BYTES:
        raise ValueError("input exceeds 16 MiB")
    with path.open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("input exceeds 16 MiB")
    if not data:
        raise ValueError("input is empty")
    if kind == "parser_evidence" and data not in EVIDENCE_FLAGS:
        raise ValueError("expected one documented parser flag with no trailing newline")
    return data


def describe_match(match):
    return {
        "rule": match.rule,
        "tags": match.tags,
        "meta": match.meta,
        "locations": [
            {
                "string": item.identifier,
                "offsets": [instance.offset for instance in item.instances[:MAX_LOCATIONS]],
            }
            for item in match.strings
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind", choices=KINDS, required=True)
    parser.add_argument("paths", type=Path, nargs="+", help="extracted artifact files of the selected kind")
    args = parser.parse_args()

    result = {"artifact_kind": args.kind, "engine_version": yara.__version__, "artifacts": []}
    try:
        rules = compile_kind(args.kind)
    except (OSError, ValueError, yara.Error, yara.WarningError) as error:
        result.update(status="incomplete", error=f"rule compilation failed: {error}")
        print(json.dumps(result, indent=2))
        return 2

    complete = True
    for path in args.paths:
        entry = {"path": str(path)}
        try:
            data = read_artifact(path, args.kind)
            hits = rules.match(data=data, timeout=TIMEOUT_SECONDS, warnings_callback=fail_on_scan_warning)
            entry.update(status="scanned", matches=[describe_match(match) for match in hits])
        except (OSError, ValueError, yara.Error, yara.WarningError) as error:
            complete = False
            entry.update(status="incomplete", error=str(error))
        result["artifacts"].append(entry)
    result["status"] = "completed" if complete else "incomplete"
    print(json.dumps(result, indent=2))
    return 0 if complete else 2


def fail_on_scan_warning(warning_type, message):
    raise ValueError(f"YARA scan warning {warning_type}: {message}")


if __name__ == "__main__":
    sys.exit(main())

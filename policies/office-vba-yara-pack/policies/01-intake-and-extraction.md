# Intake and extraction policy

## Required scan record

Create a record for each submitted document keyed by its original SHA-256. Record its claimed and identified formats, intake policy version, parser and disassembler versions, rule-pack version or commit, and scan engine version. Record one coverage row per applicable artifact or artifact class with a stable artifact ID, parent ID, source location, extraction status, and scan status.

Use these coverage states for each applicable surface.

| State | Meaning |
| --- | --- |
| `complete` | The expected artifacts were inventoried, extracted, and scanned without errors or omissions. |
| `not_applicable` | The parser verified absence or the format has no such surface. Record the reason. |
| `incomplete` | Inspection failed, was skipped, returned ambiguous data, hit a resource limit, or required a parser that could not handle the format. Record the cause. |

Run extraction on the original submission. The PR diff helps reviewers see changes, but unchanged modules and embedded objects can still affect the current submission. Keep input and derived files immutable for the duration of the job. Bind scan and review outcomes to the original SHA-256 and scanner configuration.

## Format and extraction routing

| Input surface | Inventory and extraction | Scanner route |
| --- | --- | --- |
| Word, Excel and PowerPoint OOXML, including macro-enabled documents, templates and add-ins | Identify the package from its content. Inventory content types, relationships, all VBA projects and embedded objects. Find VBA projects by package structure and content, including `word/vbaProject.bin`, `xl/vbaProject.bin` and `ppt/vbaProject.bin` when present. Use a VBA-aware parser to decompress modules and interpret their code pages. | One `vba` input per module and one `pcode` input per disassembled module where compiled code is present. Scan extracted relationship records, decoded DDE-capable field instructions, and embedded objects separately. |
| Legacy compound binary Office, including `.doc`, `.xls`, `.ppt` and supported templates | Enumerate compound storage and embedded objects. Use a parser that supports the identified container and its VBA and XLM surfaces. | Route the extracted VBA, p-code, XLM and child objects by their identified types. |
| Excel `.xlsb`, legacy XLM workbooks and supported `.slk` inputs | Use a format-aware extractor for Excel 4.0 macro sheets, defined names and formulas. Inspect hidden and very hidden macro sheets and preserve sheet and cell identifiers. Include the VBA path separately where present. | One `xlm` text input per macro sheet. Emit formulas and canonical defined-name lines such as `NAME _xlnm.Auto_Open = MacroSheet!A1`. Scan raw formula text and separately labelled static reconstructions if available. |
| OOXML external content | Parse relationships without resolving them. Serialise **one relationship element per file**, or export one complete decoded field instruction per file. Reassemble Word field text split across XML runs before scanning. Preserve source part, element ID or field ID. | `office_xml`. The rule set matches selected textual indicators. Maintain a separate structural inventory of external targets, relationship types and DDE fields. |
| Embedded files, OLE streams, packages and ActiveX content | Inventory object references and extract material payloads. Recurse into nested Office containers under the same limits. Preserve the object type, path and parent hash. | `payload` for individual binaries or scripts. Run the appropriate document extraction routes on nested documents. Additional ActiveX-specific or other exploit analysis belongs in separate controls. |
| Parser findings | Translate verified extraction findings into the trusted flag format below. | `parser_evidence`, one flag file per finding. |

Declare support by format and parser version. For RTF, Access, PDF, legacy presentations or other formats without verified end-to-end coverage, route to a supported workflow or hold. A filename extension, a successful ZIP listing, a raw YARA scan or an extractor returning zero items is insufficient to establish macro absence by itself.

### VBA source and compiled VBA

1. Inventory VBA projects and modules, including forms, class modules and host document modules. Preserve the original source, code page, project and stream identifiers, source hash and offsets where available.
2. Scan decompressed source as UTF-8. Preserve the original extracted text and scan a separate normalised copy where useful. Decode constant expressions only within bounded, static routines. Record the transform and retain the source-to-artifact mapping. Capture string literals in the diff.
3. Disassemble available compiled code with a compatible parser and preserve per-module boundaries. Run p-code rules against the disassembly. Compare source and compiled code by module. Use project and stream identity, decoded statements, call names and relevant constants to assess differences. Account for compiler artefacts, renamed identifiers, line continuations and module attributes. Treat unresolved or unsupported disassembly as incomplete coverage when compiled code is present or its presence cannot be resolved.
4. Emit the following flags only from trusted pipeline code. Each evidence file contains exactly one flag in ASCII with no BOM or trailing newline. Retain the associated document and module ID, extractor version and supporting evidence in the scan record.

| Flag | Emit when |
| --- | --- |
| `VBA_STOMPING_SUSPECTED` | A compatible comparison reports a meaningful discrepancy between the source and p-code of the same module. |
| `VBA_PCODE_WITH_EMPTY_SOURCE` | Meaningful compiled instructions exist for a module whose source is confirmed absent or empty after successful inspection. |
| `VBA_ANALYSIS_INCOMPLETE` | A required VBA extraction, disassembly or comparison could not be completed. |

Flag records must be derived from parser output. Keep submitted filenames, source text, document comments and user-supplied status files outside the trusted evidence channel. VBA stomping is an integrity finding and may need version-aware confirmation. Compiled-code presence and differing raw source and p-code hashes are expected by themselves.

## Parser and runner controls

- Use a disposable extraction worker with restricted permissions, isolated staging and no outbound network. Keep signing credentials outside the worker. Disable XML external entities, DTD processing and external target retrieval.
- Stream extracted bytes with limits for the input, each expanded part, total expansion, entry count, recursion depth, per-job time and memory. Reject traversal paths, absolute paths, duplicate or ambiguous package members and symlink entries. Prefer names assigned by the worker.
- Treat encrypted documents, corrupt structures, unsupported versions, timeouts and exceeded limits as incomplete unless the document is successfully reinspected through an authorised route.
- The provided matcher accepts one or more already-extracted files per invocation. It limits each input to 16 MiB and gives YARA 10 seconds per artifact. Apply additional job-wide limits in the extraction or orchestration layer.
- Keep the original and derived artifacts in access-controlled storage. Export rule IDs, artifact identifiers, coverage and offsets by default. Store sensitive excerpts separately for reviewers. Use approved internal destinations for reputation checks and sandbox execution.

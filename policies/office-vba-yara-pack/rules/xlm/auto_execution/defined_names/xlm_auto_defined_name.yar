rule Office_XLM_XlmAutoDefinedName : xlm auto_execution
{
    meta:
        id = "OFM-XLM-0101"
        description = "Extractor emits an Excel 4.0 macro-sheet auto-execution defined name."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "xlm"
        category = "auto_execution"
        subcategory = "defined_names"
        severity = "info"
        confidence = "medium"
        false_positive = "Legacy XLM applications may initialise or clean up automatically."

    strings:
        $name = /(^|\n)[ \t]*NAME[ \t]+(_xlnm\.)?Auto_(Open|Close|Activate|Deactivate)([ \t=\r\n]|$)/ ascii wide nocase

    condition:
        $name
}

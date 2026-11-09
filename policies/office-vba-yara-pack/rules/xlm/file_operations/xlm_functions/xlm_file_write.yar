rule Office_XLM_XlmFileWrite : xlm file_operations
{
    meta:
        id = "OFM-XLM-0701"
        description = "Excel 4.0 file-open formula together with a file-write formula."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "xlm"
        category = "file_operations"
        subcategory = "xlm_functions"
        severity = "medium"
        confidence = "medium"
        false_positive = "Legacy XLM reports and data exports can write files."

    strings:
        $open = /\bFOPEN[ \t]*\(/ ascii wide nocase
        $write = /\b(FWRITE|FWRITELN)[ \t]*\(/ ascii wide nocase

    condition:
        all of them
}

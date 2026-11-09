rule Office_VBA_CloseEvents : vba auto_execution
{
    meta:
        id = "OFM-VBA-0102"
        description = "Office close or exit procedure declaration."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "auto_execution"
        subcategory = "office_events"
        severity = "info"
        confidence = "medium"
        false_positive = "Routine cleanup and workbook save actions."

    strings:
        $entry = /\bsub[ \t]+(auto_?close|autoexit|document_close|workbook_beforeclose)[ \t]*\(/ ascii wide nocase

    condition:
        $entry
}

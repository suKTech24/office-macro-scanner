rule Office_VBA_AutoOpenEvents : vba auto_execution
{
    meta:
        id = "OFM-VBA-0101"
        description = "Office startup or document-open procedure declaration."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "auto_execution"
        subcategory = "office_events"
        severity = "info"
        confidence = "medium"
        false_positive = "Routine workbook or document initialisation."
        attack = "T1059.005"

    strings:
        $entry = /\bsub[ \t]+(auto_?open|autoexec|document_open|workbook_open|workbook_activate)[ \t]*\(/ ascii wide nocase

    condition:
        $entry
}

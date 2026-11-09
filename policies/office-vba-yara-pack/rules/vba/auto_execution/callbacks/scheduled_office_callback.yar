rule Office_VBA_ScheduledOfficeCallback : vba auto_execution
{
    meta:
        id = "OFM-VBA-0103"
        description = "Excel or Word macro scheduling through an Office callback."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "auto_execution"
        subcategory = "callbacks"
        severity = "info"
        confidence = "medium"
        false_positive = "Scheduled workbook refresh and UI updates."

    strings:
        $timer = /\bApplication[ \t]*\.[ \t]*OnTime\b/ ascii wide nocase
        $key = /\bApplication[ \t]*\.[ \t]*OnKey\b/ ascii wide nocase

    condition:
        any of them
}

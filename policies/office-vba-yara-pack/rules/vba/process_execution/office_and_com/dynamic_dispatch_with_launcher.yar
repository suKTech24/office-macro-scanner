rule Office_VBA_DynamicDispatchWithLauncher : vba process_execution
{
    meta:
        id = "OFM-VBA-0306"
        description = "VBA dynamic dispatch combined with a process creation or script host marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "process_execution"
        subcategory = "office_and_com"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved add-ins can dispatch platform-specific handlers dynamically."

    strings:
        $dispatch1 = /\bCallByName[ \t(]/ ascii wide nocase
        $dispatch2 = /\bApplication[ \t]*\.[ \t]*Run[ \t(]/ ascii wide nocase
        $launch1 = "WScript.Shell" ascii wide nocase
        $launch2 = "ShellExecute" ascii wide nocase
        $launch3 = "CreateProcess" ascii wide nocase

    condition:
        any of ($dispatch*) and any of ($launch*)
}

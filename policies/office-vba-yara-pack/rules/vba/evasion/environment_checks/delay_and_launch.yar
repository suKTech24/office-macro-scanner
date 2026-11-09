rule Office_VBA_DelayAndLaunch : vba evasion
{
    meta:
        id = "OFM-VBA-0605"
        description = "Sleep API or time-based waiting logic together with a process-launch primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "evasion"
        subcategory = "environment_checks"
        severity = "medium"
        confidence = "medium"
        false_positive = "Normal integrations may wait for dependent applications."
        attack = "T1497.003"

    strings:
        $wait1 = /\bSleep[ \t(]/ ascii wide nocase
        $wait2 = "Application.Wait" ascii wide nocase
        $wait3 = "GetTickCount" ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "CreateProcess" ascii wide nocase
        $launch3 = "WScript.Shell" ascii wide nocase

    condition:
        any of ($wait*) and any of ($launch*)
}

rule Office_VBA_WindowsEventLogClear : vba defense_impairment
{
    meta:
        id = "OFM-VBA-1304"
        description = "Event log clearing command text or Clear-EventLog cmdlet."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "defense_impairment"
        subcategory = "logging"
        severity = "high"
        confidence = "high"
        false_positive = "Approved maintenance scripts can clear disposable test logs."
        attack = "T1685.005"

    strings:
        $cmd = /\bwevtutil(\.exe)?[ \t]+(cl|clear-log)[ \t]+/ ascii wide nocase
        $ps = "Clear-EventLog" ascii wide nocase

    condition:
        any of them
}

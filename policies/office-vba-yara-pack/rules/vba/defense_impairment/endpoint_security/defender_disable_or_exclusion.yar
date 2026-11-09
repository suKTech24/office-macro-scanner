rule Office_VBA_DefenderDisableOrExclusion : vba defense_impairment
{
    meta:
        id = "OFM-VBA-1302"
        description = "Defender preference commands paired with disabling or exclusion arguments."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "defense_impairment"
        subcategory = "endpoint_security"
        severity = "high"
        confidence = "high"
        false_positive = "Approved endpoint configuration and test harnesses can use these cmdlets."
        attack = "T1685"

    strings:
        $cmd1 = "Set-MpPreference" ascii wide nocase
        $cmd2 = "Add-MpPreference" ascii wide nocase
        $opt1 = "-DisableRealtimeMonitoring" ascii wide nocase
        $opt2 = "-ExclusionPath" ascii wide nocase
        $opt3 = "-ExclusionProcess" ascii wide nocase
        $opt4 = "-ExclusionExtension" ascii wide nocase

    condition:
        any of ($cmd*) and any of ($opt*)
}

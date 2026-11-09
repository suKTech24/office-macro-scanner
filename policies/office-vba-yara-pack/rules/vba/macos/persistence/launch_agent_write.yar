rule Office_VBA_LaunchAgentWrite : vba macos
{
    meta:
        id = "OFM-VBA-1703"
        description = "macOS launch agent or daemon path paired with plist or launchctl and a write or launch primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "macos"
        subcategory = "persistence"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved installers may provision an agent or daemon."
        attack = "T1543.001,T1543.004"

    strings:
        $path1 = "/Library/LaunchAgents/" ascii wide nocase
        $path2 = "/Library/LaunchDaemons/" ascii wide nocase
        $hint1 = ".plist" ascii wide nocase
        $hint2 = "launchctl" ascii wide nocase
        $act1 = "CreateTextFile" ascii wide nocase
        $act2 = "SaveToFile" ascii wide nocase
        $act3 = "MacScript" ascii wide nocase
        $act4 = "AppleScriptTask" ascii wide nocase

    condition:
        any of ($path*) and any of ($hint*) and any of ($act*)
}

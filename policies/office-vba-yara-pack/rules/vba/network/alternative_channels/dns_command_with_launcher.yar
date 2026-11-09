rule Office_VBA_DnsCommandWithLauncher : vba network
{
    meta:
        id = "OFM-VBA-0804"
        description = "DNS lookup utility or PowerShell DNS command combined with a launch surface."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network"
        subcategory = "alternative_channels"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved diagnostics can run DNS lookups from a workbook."

    strings:
        $tool1 = /\bnslookup(\.exe)?[ \t]/ ascii wide nocase
        $tool2 = "Resolve-DnsName" ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase

    condition:
        any of ($tool*) and any of ($launch*)
}

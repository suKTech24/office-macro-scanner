rule Office_VBA_HostDiscoveryCommands : vba discovery
{
    meta:
        id = "OFM-VBA-1402"
        description = "Process launch text paired with at least two common host or network discovery commands."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "discovery"
        subcategory = "host_inventory"
        severity = "info"
        confidence = "medium"
        false_positive = "Approved diagnostic macros can run multiple inventory commands."

    strings:
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase
        $tool1 = /\bwhoami(\.exe)?\b/ ascii wide nocase
        $tool2 = /\bipconfig(\.exe)?\b/ ascii wide nocase
        $tool3 = /\bsysteminfo(\.exe)?\b/ ascii wide nocase
        $tool4 = /\bnet(\.exe)?[ \t]+(user|group|view)\b/ ascii wide nocase

    condition:
        any of ($launch*) and 2 of ($tool*)
}

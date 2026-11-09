rule Office_VBA_StartupFolderWrite : vba persistence
{
    meta:
        id = "OFM-VBA-1103"
        description = "Windows Startup folder lookup or path paired with a file or shortcut write."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "persistence"
        subcategory = "windows_logon"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved desktop deployment and sign-in helpers may install shortcuts."
        attack = "T1547.001"

    strings:
        $start1 = /SpecialFolders[ \t]*\([ \t]*"(Startup|AllUsersStartup)"/ ascii wide nocase
        $start2 = "\\Start Menu\\Programs\\Startup\\" ascii wide nocase
        $write1 = "CreateShortcut" ascii wide nocase
        $write2 = "CopyFile" ascii wide nocase
        $write3 = "SaveToFile" ascii wide nocase

    condition:
        any of ($start*) and any of ($write*)
}

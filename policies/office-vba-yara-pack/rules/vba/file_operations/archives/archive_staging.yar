rule Office_VBA_ArchiveStaging : vba file_operations
{
    meta:
        id = "OFM-VBA-0704"
        description = "Archive command text paired with an archive extension or compression mode and a process launcher."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "file_operations"
        subcategory = "archives"
        severity = "medium"
        confidence = "medium"
        false_positive = "Reporting and backups may compress data for approved delivery."
        attack = "T1560.001"

    strings:
        $archive1 = "Compress-Archive" ascii wide nocase
        $archive2 = "7z.exe" ascii wide nocase
        $archive3 = "tar.exe" ascii wide nocase
        $hint1 = ".zip" ascii wide nocase
        $hint2 = ".7z" ascii wide nocase
        $hint3 = "-Compress" ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase

    condition:
        any of ($archive*) and any of ($hint*) and any of ($launch*)
}

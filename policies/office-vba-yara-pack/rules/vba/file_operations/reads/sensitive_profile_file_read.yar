rule Office_VBA_SensitiveProfileFileRead : vba file_operations
{
    meta:
        id = "OFM-VBA-0705"
        description = "Local file read paired with browser history, remote access configuration, or key file indicators."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "file_operations"
        subcategory = "reads"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved profile backup and migration tools may read these locations."
        attack = "T1552.004"

    strings:
        $target1 = "\\.ssh\\id_rsa" ascii wide nocase
        $target2 = "\\.ssh\\id_ed25519" ascii wide nocase
        $target3 = "\\User Data\\Default\\History" ascii wide nocase
        $target4 = "\\FileZilla\\sitemanager.xml" ascii wide nocase
        $read1 = "OpenTextFile" ascii wide nocase
        $read2 = /\bFor[ \t]+(Input|Binary)[ \t]+(Access[ \t]+Read[ \t]+)?As[ \t]+#/ ascii wide nocase
        $read3 = "LoadFromFile" ascii wide nocase

    condition:
        any of ($target*) and any of ($read*)
}

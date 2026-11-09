rule Office_VBA_OfficeStartupPathWrite : vba persistence
{
    meta:
        id = "OFM-VBA-1101"
        description = "Office startup location or template reference paired with a save or copy primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "persistence"
        subcategory = "office_startup"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved Office add-ins and templates can use startup paths."
        attack = "T1137"

    strings:
        $loc1 = "XLSTART" ascii wide nocase
        $loc2 = "NormalTemplate" ascii wide nocase
        $loc3 = "Normal.dotm" ascii wide nocase
        $loc4 = /\b(Application\.)?StartupPath\b/ ascii wide nocase
        $write1 = "SaveAs" ascii wide nocase
        $write2 = "SaveCopyAs" ascii wide nocase
        $write3 = "CopyFile" ascii wide nocase
        $write4 = "SaveToFile" ascii wide nocase
        $write5 = /\bNormalTemplate[ \t]*\.[ \t]*Save\b/ ascii wide nocase

    condition:
        any of ($loc*) and any of ($write*)
}

rule Office_VBA_HiddenFileAttributes : vba evasion
{
    meta:
        id = "OFM-VBA-0607"
        description = "File attribute modification using hidden or system flags."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "evasion"
        subcategory = "concealment"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved installers can hide support files."
        attack = "T1564.001"

    strings:
        $set = /\bSetAttr[ \t(]/ ascii wide nocase
        $flag1 = "vbHidden" ascii wide nocase
        $flag2 = "vbSystem" ascii wide nocase

    condition:
        $set and any of ($flag*)
}

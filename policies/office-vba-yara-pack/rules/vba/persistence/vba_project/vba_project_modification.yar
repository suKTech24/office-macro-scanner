rule Office_VBA_VbaProjectModification : vba persistence
{
    meta:
        id = "OFM-VBA-1102"
        description = "VBA project object access paired with source editing, module import or organiser copy."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "persistence"
        subcategory = "vba_project"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved developer utilities and deployment scripts can modify VBA projects."
        attack = "T1137"

    strings:
        $project1 = "VBProject" ascii wide nocase
        $project2 = "VBComponents" ascii wide nocase
        $edit1 = "AddFromString" ascii wide nocase
        $edit2 = "InsertLines" ascii wide nocase
        $edit3 = "ReplaceLine" ascii wide nocase
        $edit4 = "DeleteLines" ascii wide nocase
        $edit5 = /\bVBComponents[ \t]*\.[ \t]*Import\b/ ascii wide nocase
        $edit6 = "OrganizerCopy" ascii wide nocase

    condition:
        any of ($project*) and any of ($edit*)
}

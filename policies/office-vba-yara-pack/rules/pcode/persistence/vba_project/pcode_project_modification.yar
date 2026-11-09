rule Office_PCD_PcodeProjectModification : pcode persistence
{
    meta:
        id = "OFM-PCD-1101"
        description = "P-code member loads for VBA project access and an edit or import opcode."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "pcode"
        category = "persistence"
        subcategory = "vba_project"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved VBA developer utilities may edit modules."
        attack = "T1137"

    strings:
        $project = /\b(MemLd|MemLdWith)[ \t]+(VBProject|VBComponents)\b/ ascii wide nocase
        $edit = /\b(ArgsMemCall|ArgsMemCallWith|ArgsMemLd|ArgsMemLdWith)[ \t]+(\(Call\)[ \t]+)?(AddFromString|InsertLines|ReplaceLine|DeleteLines|Import)\b/ ascii wide nocase

    condition:
        all of them
}

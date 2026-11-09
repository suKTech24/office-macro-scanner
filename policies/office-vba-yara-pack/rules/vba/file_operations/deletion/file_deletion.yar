rule Office_VBA_FileDeletion : vba file_operations
{
    meta:
        id = "OFM-VBA-0703"
        description = "Direct VBA file deletion or file-system automation deletion member."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "file_operations"
        subcategory = "deletion"
        severity = "medium"
        confidence = "medium"
        false_positive = "Benign cleanup often deletes temporary working files."

    strings:
        $delete1 = /\bKill[ \t]+["A-Za-z_]/ ascii wide nocase
        $delete2 = /\.[ \t]*DeleteFile[ \t(]/ ascii wide nocase
        $delete3 = /\.[ \t]*DeleteFolder[ \t(]/ ascii wide nocase

    condition:
        any of them
}

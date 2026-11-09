rule Office_VBA_AdodbStreamBinarySave : vba file_operations
{
    meta:
        id = "OFM-VBA-0702"
        description = "ADODB.Stream binary body or binary stream type paired with SaveToFile."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "file_operations"
        subcategory = "writes"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved VBA integrations regularly save binary attachments."

    strings:
        $stream = "ADODB.Stream" ascii wide nocase
        $save = "SaveToFile" ascii wide nocase
        $binary1 = "ResponseBody" ascii wide nocase
        $binary2 = "adTypeBinary" ascii wide nocase
        $binary3 = /\.[ \t]*Type[ \t]*=[ \t]*1\b/ ascii wide nocase

    condition:
        $stream and $save and any of ($binary*)
}

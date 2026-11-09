rule Office_VBA_Base64DecoderOrXmlTypedValue : vba evasion
{
    meta:
        id = "OFM-VBA-0602"
        description = "Base64 conversion API or MSXML typed value paired with a Base64 data type."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "evasion"
        subcategory = "encoding"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved file transport and XML integrations regularly decode Base64."
        attack = "T1140"

    strings:
        $crypt = "CryptStringToBinary" ascii wide nocase
        $datatype = "bin.base64" ascii wide nocase
        $typed = "NodeTypedValue" ascii wide nocase

    condition:
        $crypt or ($datatype and $typed)
}

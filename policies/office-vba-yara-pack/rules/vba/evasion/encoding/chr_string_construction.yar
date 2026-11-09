rule Office_VBA_ChrStringConstruction : vba evasion
{
    meta:
        id = "OFM-VBA-0601"
        description = "Repeated Chr or ChrW character construction alongside string concatenation."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "evasion"
        subcategory = "encoding"
        severity = "medium"
        confidence = "medium"
        false_positive = "Localisation, text clean-up and format conversion often use Chr."
        attack = "T1027"

    strings:
        $chr = /\bChr[WB]?\$?[ \t]*\([ \t]*(&H[0-9a-f]{1,6}|[0-9]{1,7})[ \t]*\)/ ascii wide nocase
        $concat = /&[ \t]*Chr[WB]?\$?[ \t]*\(/ ascii wide nocase

    condition:
        #chr >= 6 and $concat
}

rule Office_VBA_ReversedOrDecomposedStrings : vba evasion
{
    meta:
        id = "OFM-VBA-0603"
        description = "String reversal combined with string splitting or replacement."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "evasion"
        subcategory = "encoding"
        severity = "medium"
        confidence = "medium"
        false_positive = "Benign data transformations can combine these functions."
        attack = "T1027"

    strings:
        $reverse = /\bStrReverse[ \t]*\(/ ascii wide nocase
        $transform1 = /\bReplace\$?[ \t]*\(/ ascii wide nocase
        $transform2 = /\bSplit[ \t]*\(/ ascii wide nocase

    condition:
        $reverse and any of ($transform*)
}

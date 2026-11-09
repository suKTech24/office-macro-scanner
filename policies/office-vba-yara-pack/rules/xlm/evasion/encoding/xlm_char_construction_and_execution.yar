rule Office_XLM_XlmCharConstructionAndExecution : xlm evasion
{
    meta:
        id = "OFM-XLM-0601"
        description = "Repeated Excel 4.0 CHAR construction with EXEC or CALL."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "xlm"
        category = "evasion"
        subcategory = "encoding"
        severity = "high"
        confidence = "medium"
        false_positive = "Some legacy models construct text before calling an approved utility."
        attack = "T1027"

    strings:
        $char = /\bCHAR[ \t]*\([ \t]*[0-9]{1,3}[ \t]*\)/ ascii wide nocase
        $launch = /\b(EXEC|CALL)[ \t]*\(/ ascii wide nocase

    condition:
        #char >= 4 and $launch
}

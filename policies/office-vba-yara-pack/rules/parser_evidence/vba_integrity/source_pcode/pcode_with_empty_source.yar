rule Office_EVD_PcodeWithEmptySource : parser_evidence vba_integrity
{
    meta:
        id = "OFM-EVD-1802"
        description = "A trusted parser reports meaningful compiled VBA instructions with missing or empty source for the same module."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "parser_evidence"
        category = "vba_integrity"
        subcategory = "source_pcode"
        severity = "high"
        confidence = "high"
        false_positive = "Empty source from incomplete parsing or failed decoding can resemble a mismatch."

    strings:
        $flag = /^VBA_PCODE_WITH_EMPTY_SOURCE$/ ascii wide nocase

    condition:
        $flag
}

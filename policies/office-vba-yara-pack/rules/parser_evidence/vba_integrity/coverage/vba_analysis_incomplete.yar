rule Office_EVD_VbaAnalysisIncomplete : parser_evidence vba_integrity
{
    meta:
        id = "OFM-EVD-1803"
        description = "A trusted parser reports a coverage failure on a VBA project requiring inspection."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "parser_evidence"
        category = "vba_integrity"
        subcategory = "coverage"
        severity = "high"
        confidence = "medium"
        false_positive = "Malformed, encrypted or version-incompatible documents may cause analysis failure."

    strings:
        $flag = /^VBA_ANALYSIS_INCOMPLETE$/ ascii wide nocase

    condition:
        $flag
}

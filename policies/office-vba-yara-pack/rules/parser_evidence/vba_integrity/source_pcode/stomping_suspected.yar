rule Office_EVD_StompingSuspected : parser_evidence vba_integrity
{
    meta:
        id = "OFM-EVD-1801"
        description = "A trusted parser or adapter reports a suspected source and p-code mismatch."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "parser_evidence"
        category = "vba_integrity"
        subcategory = "source_pcode"
        severity = "high"
        confidence = "high"
        false_positive = "Unsupported disassembly, parser bugs or version artifacts can create apparent mismatches."

    strings:
        $flag = /^VBA_STOMPING_SUSPECTED$/ ascii wide nocase

    condition:
        $flag
}

rule Office_VBA_AmsiTamperIndicators : vba defense_impairment
{
    meta:
        id = "OFM-VBA-1303"
        description = "AMSI scan routine and memory protection or patch-related identifiers appear together."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "defense_impairment"
        subcategory = "endpoint_security"
        severity = "high"
        confidence = "high"
        false_positive = "Approved endpoint security research and instrumentation may contain these markers."
        attack = "T1685"

    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide nocase
        $amsi2 = "AmsiScanString" ascii wide nocase
        $patch1 = "VirtualProtect" ascii wide nocase
        $patch2 = "WriteProcessMemory" ascii wide nocase
        $patch3 = "RtlMoveMemory" ascii wide nocase

    condition:
        any of ($amsi*) and any of ($patch*)
}

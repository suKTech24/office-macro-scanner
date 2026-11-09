rule Office_PCD_PcodeAmsiMemoryMarkers : pcode defense_impairment
{
    meta:
        id = "OFM-PCD-1301"
        description = "P-code artifact contains AMSI scan entry points and memory patching API names."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "pcode"
        category = "defense_impairment"
        subcategory = "endpoint_security"
        severity = "high"
        confidence = "high"
        false_positive = "Approved endpoint security research and instrumentation may use these APIs."
        attack = "T1685"

    strings:
        $amsi1 = "AmsiScanBuffer" ascii wide nocase
        $amsi2 = "AmsiScanString" ascii wide nocase
        $patch1 = "VirtualProtect" ascii wide nocase
        $patch2 = "WriteProcessMemory" ascii wide nocase

    condition:
        any of ($amsi*) and any of ($patch*)
}

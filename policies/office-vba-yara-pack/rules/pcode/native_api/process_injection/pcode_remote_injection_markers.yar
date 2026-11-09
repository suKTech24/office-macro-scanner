rule Office_PCD_PcodeRemoteInjectionMarkers : pcode native_api
{
    meta:
        id = "OFM-PCD-0401"
        description = "P-code artifact contains process access, remote memory write and remote thread markers."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "pcode"
        category = "native_api"
        subcategory = "process_injection"
        severity = "high"
        confidence = "high"
        false_positive = "Authorised diagnostics can contain similar API names."
        attack = "T1055"

    strings:
        $open = "OpenProcess" ascii wide nocase
        $write = "WriteProcessMemory" ascii wide nocase
        $thread1 = "CreateRemoteThread" ascii wide nocase
        $thread2 = "NtCreateThreadEx" ascii wide nocase

    condition:
        $open and $write and any of ($thread*)
}

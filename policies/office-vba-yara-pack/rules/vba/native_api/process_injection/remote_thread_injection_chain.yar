rule Office_VBA_RemoteThreadInjectionChain : vba native_api
{
    meta:
        id = "OFM-VBA-0401"
        description = "Process access, remote memory write, and a remote thread creation primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "native_api"
        subcategory = "process_injection"
        severity = "high"
        confidence = "high"
        false_positive = "Authorised low-level instrumentation could contain this sequence."
        attack = "T1055"

    strings:
        $open = "OpenProcess" ascii wide nocase
        $write = "WriteProcessMemory" ascii wide nocase
        $thread1 = "CreateRemoteThread" ascii wide nocase
        $thread2 = "NtCreateThreadEx" ascii wide nocase

    condition:
        $open and $write and any of ($thread*)
}

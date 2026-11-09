rule Office_VBA_ApcInjectionChain : vba native_api
{
    meta:
        id = "OFM-VBA-0402"
        description = "Remote allocation and memory write paired with APC queueing."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "native_api"
        subcategory = "process_injection"
        severity = "high"
        confidence = "high"
        false_positive = "Instrumentation and debugging utilities may use these APIs."
        attack = "T1055.004"

    strings:
        $alloc = "VirtualAllocEx" ascii wide nocase
        $write = "WriteProcessMemory" ascii wide nocase
        $queue1 = "QueueUserAPC" ascii wide nocase
        $queue2 = "NtQueueApcThread" ascii wide nocase

    condition:
        $alloc and $write and any of ($queue*)
}

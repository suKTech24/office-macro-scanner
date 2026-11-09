rule Office_VBA_InProcessMemoryExecution : vba native_api
{
    meta:
        id = "OFM-VBA-0403"
        description = "Native memory allocation, byte copy and thread or callback execution markers."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "native_api"
        subcategory = "memory_execution"
        severity = "high"
        confidence = "high"
        false_positive = "Approved native bridges can implement unusual callbacks."
        attack = "T1620"

    strings:
        $mem1 = "VirtualAlloc" ascii wide nocase
        $mem2 = "VirtualProtect" ascii wide nocase
        $copy1 = "RtlMoveMemory" ascii wide nocase
        $copy2 = "CopyMemory" ascii wide nocase
        $run1 = /\bCreateThread\b/ ascii wide nocase
        $run2 = "CallWindowProc" ascii wide nocase
        $run3 = "EnumSystemLocales" ascii wide nocase

    condition:
        any of ($mem*) and any of ($copy*) and any of ($run*)
}

rule Office_VBA_ProcessHollowingPrimitives : vba native_api
{
    meta:
        id = "OFM-VBA-0405"
        description = "Suspended-process indicators combined with unmapping or thread-context manipulation and resumption."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "native_api"
        subcategory = "memory_execution"
        severity = "high"
        confidence = "high"
        false_positive = "Specialised test or debugging tools may use similar primitives."
        attack = "T1055.012"

    strings:
        $create = "CreateProcess" ascii wide nocase
        $suspended = "CREATE_SUSPENDED" ascii wide nocase
        $change1 = "NtUnmapViewOfSection" ascii wide nocase
        $change2 = "SetThreadContext" ascii wide nocase
        $resume = "ResumeThread" ascii wide nocase

    condition:
        $create and $suspended and any of ($change*) and $resume
}

rule Office_VBA_LsassMemoryAccess : vba credential_access
{
    meta:
        id = "OFM-VBA-0503"
        description = "LSASS target text plus a dump or memory read function and a process handle marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "credential_access"
        subcategory = "system_secrets"
        severity = "high"
        confidence = "high"
        false_positive = "Approved diagnostic and security tooling can collect process dumps."
        attack = "T1003.001"

    strings:
        $target = "lsass.exe" ascii wide nocase
        $dump1 = "MiniDumpWriteDump" ascii wide nocase
        $dump2 = "ReadProcessMemory" ascii wide nocase
        $access1 = "OpenProcess" ascii wide nocase
        $access2 = "comsvcs.dll" ascii wide nocase

    condition:
        $target and any of ($dump*) and any of ($access*)
}

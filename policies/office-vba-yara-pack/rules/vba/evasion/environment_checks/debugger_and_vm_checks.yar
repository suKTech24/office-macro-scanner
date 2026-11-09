rule Office_VBA_DebuggerAndVmChecks : vba evasion
{
    meta:
        id = "OFM-VBA-0604"
        description = "Debugger probes or virtual-machine fingerprints combined with an environment-query marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "evasion"
        subcategory = "environment_checks"
        severity = "medium"
        confidence = "medium"
        false_positive = "Compatibility diagnostics can identify test or virtual environments."
        attack = "T1497.001,T1622"

    strings:
        $debug1 = "IsDebuggerPresent" ascii wide nocase
        $debug2 = "CheckRemoteDebuggerPresent" ascii wide nocase
        $vm1 = "VMware" ascii wide nocase
        $vm2 = "VirtualBox" ascii wide nocase
        $vm3 = "QEMU" ascii wide nocase
        $query1 = "Win32_ComputerSystem" ascii wide nocase
        $query2 = "Win32_BIOS" ascii wide nocase
        $query3 = "GetSystemInfo" ascii wide nocase

    condition:
        any of ($debug*) or (any of ($vm*) and any of ($query*))
}

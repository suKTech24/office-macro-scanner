rule Office_VBA_WmiHostDiscovery : vba discovery
{
    meta:
        id = "OFM-VBA-1401"
        description = "WMI connection text paired with OS, process or security product discovery classes."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "discovery"
        subcategory = "host_inventory"
        severity = "info"
        confidence = "medium"
        false_positive = "Asset inventory and troubleshooting can legitimately query WMI."

    strings:
        $wmi1 = "winmgmts:" ascii wide nocase
        $wmi2 = "SWbemLocator" ascii wide nocase
        $class1 = "Win32_OperatingSystem" ascii wide nocase
        $class2 = "Win32_ComputerSystem" ascii wide nocase
        $class3 = "Win32_Process" ascii wide nocase
        $class4 = "AntiVirusProduct" ascii wide nocase

    condition:
        any of ($wmi*) and any of ($class*)
}

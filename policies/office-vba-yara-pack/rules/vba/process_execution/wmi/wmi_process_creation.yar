rule Office_VBA_WmiProcessCreation : vba process_execution
{
    meta:
        id = "OFM-VBA-0304"
        description = "WMI connection, Win32_Process and a process creation method appear in a module."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "process_execution"
        subcategory = "wmi"
        severity = "high"
        confidence = "medium"
        false_positive = "IT administration workbooks can use WMI for management."
        attack = "T1047"

    strings:
        $wmi1 = "winmgmts:" ascii wide nocase
        $wmi2 = "SWbemLocator" ascii wide nocase
        $class = "Win32_Process" ascii wide nocase
        $create = /\.[ \t]*Create[ \t(]|\bExecMethod_[ \t(]/ ascii wide nocase

    condition:
        any of ($wmi*) and $class and $create
}

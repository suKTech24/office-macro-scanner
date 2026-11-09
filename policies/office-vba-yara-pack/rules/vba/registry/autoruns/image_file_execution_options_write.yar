rule Office_VBA_ImageFileExecutionOptionsWrite : vba registry
{
    meta:
        id = "OFM-VBA-1203"
        description = "IFEO registry path with Debugger or GlobalFlag marker and a registry write primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "registry"
        subcategory = "autoruns"
        severity = "high"
        confidence = "high"
        false_positive = "Approved debugging and application diagnostics can configure IFEO."
        attack = "T1546.012"

    strings:
        $key = "Image File Execution Options" ascii wide nocase
        $setting1 = "\\Debugger" ascii wide nocase
        $setting2 = "\\GlobalFlag" ascii wide nocase
        $write1 = /\.[ \t]*RegWrite[ \t(]/ ascii wide nocase
        $write2 = "RegSetValueEx" ascii wide nocase
        $write3 = /\breg(\.exe)?[ \t]+add[ \t]+/ ascii wide nocase

    condition:
        $key and any of ($setting*) and any of ($write*)
}

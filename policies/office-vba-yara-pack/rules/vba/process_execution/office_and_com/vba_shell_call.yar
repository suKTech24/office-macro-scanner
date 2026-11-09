rule Office_VBA_VbaShellCall : vba process_execution
{
    meta:
        id = "OFM-VBA-0301"
        description = "VBA Shell call syntax outside a simple identifier substring."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "process_execution"
        subcategory = "office_and_com"
        severity = "medium"
        confidence = "medium"
        false_positive = "Trusted VBA can launch approved helper applications."
        attack = "T1059.005"

    strings:
        $shell = /\bShell[ \t]*\(|\bShell[ \t]+["A-Za-z_]/ ascii wide nocase

    condition:
        $shell
}

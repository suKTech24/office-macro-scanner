rule Office_VBA_RunKeyWrite : vba registry
{
    meta:
        id = "OFM-VBA-1202"
        description = "Windows Run or RunOnce registry path paired with a registry write primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "registry"
        subcategory = "autoruns"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved software installers can register startup entries."
        attack = "T1547.001"

    strings:
        $key = /\\CurrentVersion\\(RunOnce|Run)([\\\" \t]|$)/ ascii wide nocase
        $write1 = /\.[ \t]*RegWrite[ \t(]/ ascii wide nocase
        $write2 = "RegSetValueEx" ascii wide nocase
        $write3 = /\breg(\.exe)?[ \t]+add[ \t]+/ ascii wide nocase

    condition:
        $key and any of ($write*)
}

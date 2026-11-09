rule Office_VBA_StartupEventAndLauncher : vba execution_chains
{
    meta:
        id = "OFM-VBA-1603"
        description = "Office auto-open declaration combined with a command or script host and launcher."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "execution_chains"
        subcategory = "auto_launch"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved startup macros can start preconfigured helpers."
        attack = "T1059.005"

    strings:
        $entry = /\bsub[ \t]+(auto_?open|autoexec|document_open|workbook_open)[ \t]*\(/ ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase
        $host1 = "powershell" ascii wide nocase
        $host2 = "cmd.exe" ascii wide nocase
        $host3 = "mshta" ascii wide nocase
        $host4 = "wscript.exe" ascii wide nocase
        $host5 = "cscript.exe" ascii wide nocase

    condition:
        $entry and any of ($launch*) and any of ($host*)
}

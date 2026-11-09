rule Office_VBA_WindowsCommandInterpreter : vba command_execution
{
    meta:
        id = "OFM-VBA-0203"
        description = "A process-launch surface paired with cmd.exe /c or /k."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "command_execution"
        subcategory = "shell"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved batch automation and report generation."
        attack = "T1059.003"

    strings:
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase
        $launch3 = "ShellExecute" ascii wide nocase
        $cmd = /\bcmd(\.exe)?[ \t]+\/[ck][ \t]/ ascii wide nocase

    condition:
        any of ($launch*) and $cmd
}

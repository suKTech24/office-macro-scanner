rule Office_VBA_ScriptHostWithVbaLauncher : vba command_execution
{
    meta:
        id = "OFM-VBA-0204"
        description = "VBScript, JScript or HTA host text paired with a process-launch surface."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "command_execution"
        subcategory = "script_hosts"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved script helpers can use legacy Windows hosts."
        attack = "T1059.005"

    strings:
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase
        $launch3 = "CreateProcess" ascii wide nocase
        $host1 = "wscript.exe" ascii wide nocase
        $host2 = "cscript.exe" ascii wide nocase
        $host3 = "mshta.exe" ascii wide nocase

    condition:
        any of ($launch*) and any of ($host*)
}

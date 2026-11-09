rule Office_XLM_XlmExecCommand : xlm command_execution
{
    meta:
        id = "OFM-XLM-0201"
        description = "Excel 4.0 EXEC formula with a command interpreter or script-host marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "xlm"
        category = "command_execution"
        subcategory = "xlm_functions"
        severity = "high"
        confidence = "medium"
        false_positive = "Legacy macro sheets can run approved utilities."
        attack = "T1059"

    strings:
        $exec = /\bEXEC[ \t]*\(/ ascii wide nocase
        $tool1 = "powershell" ascii wide nocase
        $tool2 = "cmd.exe" ascii wide nocase
        $tool3 = "mshta" ascii wide nocase
        $tool4 = "wscript.exe" ascii wide nocase
        $tool5 = "rundll32" ascii wide nocase

    condition:
        $exec and any of ($tool*)
}

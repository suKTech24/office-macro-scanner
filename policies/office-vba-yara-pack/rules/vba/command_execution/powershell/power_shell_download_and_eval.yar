rule Office_VBA_PowerShellDownloadAndEval : vba command_execution
{
    meta:
        id = "OFM-VBA-0202"
        description = "PowerShell network retrieval combined with an expression or script evaluation primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "command_execution"
        subcategory = "powershell"
        severity = "high"
        confidence = "high"
        false_positive = "Bootstrap scripts may download and run sanctioned code."
        attack = "T1059.001,T1105"

    strings:
        $ps = /\b(powershell|pwsh)(\.exe)?\b/ ascii wide nocase
        $get1 = "Invoke-WebRequest" ascii wide nocase
        $get2 = "DownloadString" ascii wide nocase
        $get3 = "Invoke-RestMethod" ascii wide nocase
        $eval1 = "Invoke-Expression" ascii wide nocase
        $eval2 = /\biex[ \t(]/ ascii wide nocase
        $eval3 = "ScriptBlock]::Create" ascii wide nocase

    condition:
        $ps and any of ($get*) and any of ($eval*)
}

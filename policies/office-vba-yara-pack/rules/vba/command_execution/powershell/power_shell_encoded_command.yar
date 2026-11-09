rule Office_VBA_PowerShellEncodedCommand : vba command_execution
{
    meta:
        id = "OFM-VBA-0201"
        description = "PowerShell command text together with an encoded-command switch."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "command_execution"
        subcategory = "powershell"
        severity = "high"
        confidence = "high"
        false_positive = "Administrative scripts can use encoded command arguments."
        attack = "T1059.001"

    strings:
        $ps = /\b(powershell|pwsh)(\.exe)?\b/ ascii wide nocase
        $encoded = /[ \t]-enc(odedcommand)?[ \t:]+[A-Za-z0-9+\/]{8,}/ ascii wide nocase

    condition:
        all of them
}

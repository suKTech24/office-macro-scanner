rule Office_VBA_Rundll32ScriptOrWritablePath : vba command_execution
{
    meta:
        id = "OFM-VBA-0207"
        description = "Rundll32 paired with an inline script marker or an explicit user-writable path marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "command_execution"
        subcategory = "system_binaries"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved utilities can run DLLs staged under a user profile."
        attack = "T1218.011"

    strings:
        $run = "rundll32" ascii wide nocase
        $hint1 = "javascript:" ascii wide nocase
        $hint2 = "mshtml,RunHTMLApplication" ascii wide nocase
        $hint3 = "%TEMP%" ascii wide nocase
        $hint4 = "%APPDATA%" ascii wide nocase
        $hint5 = "\\AppData\\Local\\Temp\\" ascii wide nocase

    condition:
        $run and any of ($hint*)
}

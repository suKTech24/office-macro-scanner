rule Office_VBA_Regsvr32Scriptlet : vba command_execution
{
    meta:
        id = "OFM-VBA-0206"
        description = "Regsvr32 paired with scrobj and a scriptlet or an install switch."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "command_execution"
        subcategory = "system_binaries"
        severity = "high"
        confidence = "high"
        false_positive = "Legacy registration workflows can use scriptlets."
        attack = "T1218.010"

    strings:
        $reg = "regsvr32" ascii wide nocase
        $scrobj = "scrobj.dll" ascii wide nocase
        $hint1 = ".sct" ascii wide nocase
        $hint2 = /[ \t]\/i:/ ascii wide nocase

    condition:
        $reg and $scrobj and any of ($hint*)
}

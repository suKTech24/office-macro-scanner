rule Office_VBA_MshtaRemoteOrInline : vba command_execution
{
    meta:
        id = "OFM-VBA-0205"
        description = "Mshta paired with an HTTP URL or an inline scripting scheme."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "command_execution"
        subcategory = "system_binaries"
        severity = "high"
        confidence = "high"
        false_positive = "Legacy intranet applications may launch hosted HTA content."
        attack = "T1218.005"

    strings:
        $hta = /\bmshta(\.exe)?\b/ ascii wide nocase
        $url1 = "https://" ascii wide nocase
        $url2 = "http://" ascii wide nocase
        $url3 = "javascript:" ascii wide nocase
        $url4 = "vbscript:" ascii wide nocase

    condition:
        $hta and any of ($url*)
}

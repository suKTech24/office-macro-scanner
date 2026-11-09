rule Office_VBA_HiddenProcessLaunch : vba evasion
{
    meta:
        id = "OFM-VBA-0606"
        description = "VBA process launch with a hidden-window hint."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "evasion"
        subcategory = "concealment"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved command-line automation often hides its console."
        attack = "T1564.003"

    strings:
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase
        $launch3 = "ShellExecute" ascii wide nocase
        $hide1 = "vbHide" ascii wide nocase
        $hide2 = "SW_HIDE" ascii wide nocase
        $hide3 = /-(WindowStyle|w)[ \t]+Hidden\b/ ascii wide nocase

    condition:
        any of ($launch*) and any of ($hide*)
}

rule Office_VBA_MacOsShellDownload : vba macos
{
    meta:
        id = "OFM-VBA-1702"
        description = "Mac-oriented shell or AppleScript marker and a curl or wget command with an HTTP URL."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "macos"
        subcategory = "scripting"
        severity = "high"
        confidence = "high"
        false_positive = "Approved macOS scripts can download approved content."
        attack = "T1105"

    strings:
        $mac1 = "MacScript" ascii wide nocase
        $mac2 = "AppleScriptTask" ascii wide nocase
        $mac3 = "/bin/zsh" ascii wide nocase
        $mac4 = "/bin/bash" ascii wide nocase
        $get1 = /\bcurl[ \t]/ ascii wide nocase
        $get2 = /\bwget[ \t]/ ascii wide nocase
        $url1 = "https://" ascii wide nocase
        $url2 = "http://" ascii wide nocase

    condition:
        any of ($mac*) and any of ($get*) and any of ($url*)
}

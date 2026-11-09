rule Office_VBA_AppleScriptShellCommand : vba macos
{
    meta:
        id = "OFM-VBA-1701"
        description = "AppleScript invocation marker with shell-command text or a common shell path."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "macos"
        subcategory = "scripting"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved macOS Office automation can invoke AppleScript and shell tools."
        attack = "T1059.002,T1059.004"

    strings:
        $invoke1 = "AppleScriptTask" ascii wide nocase
        $invoke2 = "MacScript" ascii wide nocase
        $command1 = "do shell script" ascii wide nocase
        $command2 = "/bin/bash" ascii wide nocase
        $command3 = "/bin/zsh" ascii wide nocase
        $command4 = "/bin/sh" ascii wide nocase

    condition:
        any of ($invoke*) and any of ($command*)
}

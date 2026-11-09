rule Office_PAY_EmbeddedScriptMarkers : payload embedded_content
{
    meta:
        id = "OFM-PAY-2002"
        description = "Standalone embedded text contains script-host or PowerShell markers and execution or download primitives."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "payload"
        category = "embedded_content"
        subcategory = "scripts"
        severity = "high"
        confidence = "medium"
        false_positive = "Some approved embedded support scripts contain these markers."

    strings:
        $context1 = "#requires -version" ascii wide nocase
        $context2 = "WScript.Shell" ascii wide nocase
        $context3 = "$ErrorActionPreference" ascii wide nocase
        $act1 = "Invoke-Expression" ascii wide nocase
        $act2 = "Invoke-WebRequest" ascii wide nocase
        $act3 = "DownloadString" ascii wide nocase
        $act4 = /\.[ \t]*(Run|Exec)[ \t(]/ ascii wide nocase

    condition:
        any of ($context*) and any of ($act*)
}

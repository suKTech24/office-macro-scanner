rule Office_VBA_CommandLineFileUpload : vba exfiltration
{
    meta:
        id = "OFM-VBA-1004"
        description = "Curl file upload or multipart file syntax with an HTTP destination and VBA process launcher."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "exfiltration"
        subcategory = "command_tools"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved automation can upload files to managed services."

    strings:
        $tool = /\bcurl(\.exe)?[ \t]/ ascii wide nocase
        $upload = /[ \t](-T|--upload-file)[ \t]+|[ \t](-F|--form)[ \t]+[^"\r\n]{0,40}=@/ ascii wide
        $url = /https?:\/\// ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = "WScript.Shell" ascii wide nocase

    condition:
        $tool and $upload and $url and any of ($launch*)
}

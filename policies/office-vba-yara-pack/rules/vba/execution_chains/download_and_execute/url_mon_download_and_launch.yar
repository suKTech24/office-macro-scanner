rule Office_VBA_UrlMonDownloadAndLaunch : vba execution_chains
{
    meta:
        id = "OFM-VBA-1602"
        description = "URLMon download API marker and process launcher in the same artifact."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "execution_chains"
        subcategory = "download_and_execute"
        severity = "high"
        confidence = "high"
        false_positive = "Approved VBA update or installation tools can download and launch a helper."
        attack = "T1105,T1059.005"

    strings:
        $download = "URLDownloadToFile" ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = /\.[ \t]*Run[ \t(]/ ascii wide nocase
        $launch3 = "ShellExecute" ascii wide nocase

    condition:
        $download and any of ($launch*)
}

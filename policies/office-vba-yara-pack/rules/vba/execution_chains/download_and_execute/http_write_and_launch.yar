rule Office_VBA_HttpWriteAndLaunch : vba execution_chains
{
    meta:
        id = "OFM-VBA-1601"
        description = "HTTP retrieval, binary file write and a process launch primitive in the same artifact."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "execution_chains"
        subcategory = "download_and_execute"
        severity = "high"
        confidence = "high"
        false_positive = "Approved updater workflows can download and launch a tool."
        attack = "T1105,T1059.005"

    strings:
        $client1 = "XMLHTTP" ascii wide nocase
        $client2 = "WinHttpRequest" ascii wide nocase
        $body = "ResponseBody" ascii wide nocase
        $save = "SaveToFile" ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = /\.[ \t]*Run[ \t(]/ ascii wide nocase
        $launch3 = "ShellExecute" ascii wide nocase

    condition:
        any of ($client*) and $body and $save and any of ($launch*)
}

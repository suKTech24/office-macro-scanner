rule Office_VBA_HttpPostWithFileOrDocumentRead : vba exfiltration
{
    meta:
        id = "OFM-VBA-1001"
        description = "HTTP POST or PUT and a send member combined with a file or document read marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "exfiltration"
        subcategory = "http_upload"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved upload, document processing, and API workflows look similar."

    strings:
        $client1 = "XMLHTTP" ascii wide nocase
        $client2 = "WinHttpRequest" ascii wide nocase
        $verb = /\.[ \t]*Open[ \t(]+["'](POST|PUT|PATCH)["']/ ascii wide nocase
        $send = /\.[ \t]*Send\b/ ascii wide nocase
        $read1 = "LoadFromFile" ascii wide nocase
        $read2 = "OpenTextFile" ascii wide nocase
        $read3 = "ActiveDocument.Content" ascii wide nocase
        $read4 = /\bFor[ \t]+(Input|Binary)[ \t]+(Access[ \t]+Read[ \t]+)?As[ \t]+#/ ascii wide nocase

    condition:
        any of ($client*) and $verb and $send and any of ($read*)
}

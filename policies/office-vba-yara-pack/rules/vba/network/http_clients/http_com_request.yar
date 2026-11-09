rule Office_VBA_HttpComRequest : vba network
{
    meta:
        id = "OFM-VBA-0801"
        description = "Windows HTTP COM automation class with Open and Send members."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network"
        subcategory = "http_clients"
        severity = "medium"
        confidence = "medium"
        false_positive = "Business integrations often use these objects for HTTP requests."
        attack = "T1071.001"

    strings:
        $client1 = "XMLHTTP" ascii wide nocase
        $client2 = "WinHttp.WinHttpRequest" ascii wide nocase
        $open = /\.[ \t]*Open[ \t(]/ ascii wide nocase
        $send = /\.[ \t]*Send\b/ ascii wide nocase

    condition:
        any of ($client*) and $open and $send
}

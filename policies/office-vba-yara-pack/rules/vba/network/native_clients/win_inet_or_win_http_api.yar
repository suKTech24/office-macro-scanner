rule Office_VBA_WinInetOrWinHttpApi : vba network
{
    meta:
        id = "OFM-VBA-0803"
        description = "Native WinInet or WinHTTP API markers covering session setup and data transfer."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network"
        subcategory = "native_clients"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved VBA native bridges can use the same networking APIs."
        attack = "T1071.001"

    strings:
        $start1 = "InternetOpen" ascii wide nocase
        $start2 = "WinHttpOpen" ascii wide nocase
        $transfer1 = "InternetReadFile" ascii wide nocase
        $transfer2 = "HttpSendRequest" ascii wide nocase
        $transfer3 = "WinHttpReadData" ascii wide nocase

    condition:
        any of ($start*) and any of ($transfer*)
}

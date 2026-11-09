rule Office_VBA_UrlShortenerInNetworkModule : vba network_obfuscation
{
    meta:
        id = "OFM-VBA-0902"
        description = "Known short-link service text paired with VBA HTTP client or download primitives."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network_obfuscation"
        subcategory = "url_forms"
        severity = "medium"
        confidence = "medium"
        false_positive = "Trusted documentation and business systems can use shortened URLs."

    strings:
        $host = /https?:\/\/(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly)([:\/?" \t]|$)/ ascii wide nocase
        $net1 = "XMLHTTP" ascii wide nocase
        $net2 = "WinHttpRequest" ascii wide nocase
        $net3 = "URLDownloadToFile" ascii wide nocase

    condition:
        $host and any of ($net*)
}

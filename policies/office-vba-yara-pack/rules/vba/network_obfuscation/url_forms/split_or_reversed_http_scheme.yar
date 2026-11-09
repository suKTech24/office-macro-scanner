rule Office_VBA_SplitOrReversedHttpScheme : vba network_obfuscation
{
    meta:
        id = "OFM-VBA-0903"
        description = "A split HTTP scheme or reversed scheme literal paired with networking primitives."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network_obfuscation"
        subcategory = "url_forms"
        severity = "medium"
        confidence = "medium"
        false_positive = "Some integrations build endpoints from configuration fragments."
        attack = "T1027"

    strings:
        $scheme1 = /"htt"[ \t]*&[ \t]*"ps?:\/\// ascii wide nocase
        $scheme2 = /"https?"[ \t]*&[ \t]*":\/\// ascii wide nocase
        $scheme3 = /StrReverse[ \t]*\([ \t]*"\/\/:[s]?ptth"/ ascii wide nocase
        $net1 = "XMLHTTP" ascii wide nocase
        $net2 = "WinHttpRequest" ascii wide nocase
        $net3 = "URLDownloadToFile" ascii wide nocase

    condition:
        any of ($scheme*) and any of ($net*)
}

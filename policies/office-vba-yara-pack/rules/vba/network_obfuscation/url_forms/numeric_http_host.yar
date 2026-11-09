rule Office_VBA_NumericHttpHost : vba network_obfuscation
{
    meta:
        id = "OFM-VBA-0901"
        description = "HTTP URL using a dotted numeric host or a single large decimal host."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network_obfuscation"
        subcategory = "url_forms"
        severity = "medium"
        confidence = "medium"
        false_positive = "Intranet test and management systems may be addressed by IP."

    strings:
        $host = /https?:\/\/([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9]{8,10})([:\/"? \t]|$)/ ascii wide nocase

    condition:
        $host
}

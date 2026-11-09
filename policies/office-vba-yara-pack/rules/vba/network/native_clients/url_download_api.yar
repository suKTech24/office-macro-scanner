rule Office_VBA_UrlDownloadApi : vba network
{
    meta:
        id = "OFM-VBA-0802"
        description = "Native URLMon download function with a URLMon library marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network"
        subcategory = "native_clients"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved update helpers may use URLMon for downloads."
        attack = "T1105"

    strings:
        $lib = "urlmon" ascii wide nocase
        $api1 = "URLDownloadToFile" ascii wide nocase
        $api2 = "URLDownloadToCacheFile" ascii wide nocase

    condition:
        $lib and any of ($api*)
}

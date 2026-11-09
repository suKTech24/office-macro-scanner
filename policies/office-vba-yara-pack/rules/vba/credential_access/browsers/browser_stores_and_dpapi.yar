rule Office_VBA_BrowserStoresAndDpapi : vba credential_access
{
    meta:
        id = "OFM-VBA-0502"
        description = "Browser credential store indicators combined with a DPAPI decryption function."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "credential_access"
        subcategory = "browsers"
        severity = "high"
        confidence = "high"
        false_positive = "Approved browser migration or recovery tools can access these stores."
        attack = "T1555.003"

    strings:
        $decrypt = "CryptUnprotectData" ascii wide nocase
        $store1 = "Login Data" ascii wide nocase
        $store2 = "logins.json" ascii wide nocase
        $store3 = "key4.db" ascii wide nocase
        $store4 = "Network\\Cookies" ascii wide nocase

    condition:
        $decrypt and any of ($store*)
}

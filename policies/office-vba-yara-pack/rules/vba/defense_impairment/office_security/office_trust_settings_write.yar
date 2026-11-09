rule Office_VBA_OfficeTrustSettingsWrite : vba defense_impairment
{
    meta:
        id = "OFM-VBA-1301"
        description = "Registry write combined with Office Security or Trusted Locations and a sensitive setting marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "defense_impairment"
        subcategory = "office_security"
        severity = "high"
        confidence = "medium"
        false_positive = "Managed Office administration may set legitimate trust policy."
        attack = "T1685"

    strings:
        $office = "\\Microsoft\\Office\\" ascii wide nocase
        $loc1 = "\\Security\\" ascii wide nocase
        $loc2 = "\\Trusted Locations\\" ascii wide nocase
        $setting1 = "AccessVBOM" ascii wide nocase
        $setting2 = "VBAWarnings" ascii wide nocase
        $setting3 = "DisableAllActiveX" ascii wide nocase
        $setting4 = "\\Trusted Locations\\" ascii wide nocase
        $write1 = /\.[ \t]*RegWrite[ \t(]/ ascii wide nocase
        $write2 = "RegSetValueEx" ascii wide nocase
        $write3 = /\breg(\.exe)?[ \t]+add[ \t]+/ ascii wide nocase

    condition:
        $office and any of ($loc*) and any of ($setting*) and any of ($write*)
}

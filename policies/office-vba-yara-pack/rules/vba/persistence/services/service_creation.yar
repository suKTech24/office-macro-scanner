rule Office_VBA_ServiceCreation : vba persistence
{
    meta:
        id = "OFM-VBA-1105"
        description = "Windows service creation via command-line or native API declaration."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "persistence"
        subcategory = "services"
        severity = "high"
        confidence = "medium"
        false_positive = "Administrative automation can create approved services."
        attack = "T1543.003"

    strings:
        $command = /\bsc(\.exe)?[ \t]+create[ \t]+/ ascii wide nocase
        $api = /\b(CreateService[AW]?)\b/ ascii wide nocase
        $lib = "advapi32" ascii wide nocase

    condition:
        $command or ($api and $lib)
}

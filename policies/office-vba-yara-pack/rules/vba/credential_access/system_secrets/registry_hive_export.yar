rule Office_VBA_RegistryHiveExport : vba credential_access
{
    meta:
        id = "OFM-VBA-0504"
        description = "reg.exe save command text paired with a protected Windows hive name."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "credential_access"
        subcategory = "system_secrets"
        severity = "high"
        confidence = "high"
        false_positive = "Administrative backup and recovery workflows may export hives."
        attack = "T1003.002,T1003.004"

    strings:
        $save = /\breg(\.exe)?[ \t]+save[ \t]+/ ascii wide nocase
        $hive = /\b(HKLM|HKEY_LOCAL_MACHINE)\\(SAM|SECURITY|SYSTEM)\b/ ascii wide nocase

    condition:
        all of them
}

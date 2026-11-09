rule Office_VBA_RegistryWriteOrDelete : vba registry
{
    meta:
        id = "OFM-VBA-1201"
        description = "Registry modification via Windows Script Host, native API names or reg.exe command text."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "registry"
        subcategory = "modification"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved setup utilities may update application settings."
        attack = "T1112"

    strings:
        $wsh = /\.[ \t]*Reg(Write|Delete)[ \t(]/ ascii wide nocase
        $api = /\bReg(SetValueEx|CreateKeyEx|DeleteKey|DeleteValue)[AW]?\b/ ascii wide nocase
        $cmd = /\breg(\.exe)?[ \t]+(add|delete)[ \t]+/ ascii wide nocase

    condition:
        any of them
}

rule Office_VBA_RegistryRead : vba registry
{
    meta:
        id = "OFM-VBA-1204"
        description = "Direct Windows Script Host registry read or native registry query API."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "registry"
        subcategory = "discovery"
        severity = "info"
        confidence = "medium"
        false_positive = "Routine applications commonly read Windows or application settings."

    strings:
        $wsh = /\.[ \t]*RegRead[ \t(]/ ascii wide nocase
        $api = /\bReg(QueryValueEx|GetValue)[AW]?\b/ ascii wide nocase

    condition:
        any of them
}

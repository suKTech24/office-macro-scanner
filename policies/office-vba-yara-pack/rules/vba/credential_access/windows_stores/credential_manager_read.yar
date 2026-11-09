rule Office_VBA_CredentialManagerRead : vba credential_access
{
    meta:
        id = "OFM-VBA-0501"
        description = "Credential retrieval or enumeration API associated with advapi32."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "credential_access"
        subcategory = "windows_stores"
        severity = "high"
        confidence = "medium"
        false_positive = "An approved credential integration may call Windows Credential Manager."
        attack = "T1555.004"

    strings:
        $lib = "advapi32" ascii wide nocase
        $api = /\bCred(Read|Enumerate)[AW]?\b/ ascii wide nocase

    condition:
        all of them
}

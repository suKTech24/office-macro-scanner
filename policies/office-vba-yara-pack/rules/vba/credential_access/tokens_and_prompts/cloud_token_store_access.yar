rule Office_VBA_CloudTokenStoreAccess : vba credential_access
{
    meta:
        id = "OFM-VBA-0505"
        description = "Cloud CLI or developer credential store text paired with a local file read primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "credential_access"
        subcategory = "tokens_and_prompts"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved backup or developer diagnostics may inspect these paths."
        attack = "T1552.001"

    strings:
        $store1 = "\\.aws\\credentials" ascii wide nocase
        $store2 = "\\.azure\\msal_token_cache" ascii wide nocase
        $store3 = "\\gcloud\\application_default_credentials.json" ascii wide nocase
        $store4 = "\\gh\\hosts.yml" ascii wide nocase
        $read1 = "OpenTextFile" ascii wide nocase
        $read2 = /\bFor[ \t]+(Binary|Input)[ \t]+Access[ \t]+Read\b/ ascii wide nocase
        $read3 = /\bFor[ \t]+Input[ \t]+As[ \t]+#/ ascii wide nocase

    condition:
        any of ($store*) and any of ($read*)
}

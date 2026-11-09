rule Office_VBA_PasswordPromptAndOutbound : vba credential_access
{
    meta:
        id = "OFM-VBA-0506"
        description = "A password-like input prompt paired with a network send or Outlook item send."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "credential_access"
        subcategory = "tokens_and_prompts"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved workflows may collect a password or send email for unrelated reasons."
        attack = "T1056.002"

    strings:
        $prompt = /\bInputBox[ \t]*(\([ \t]*)?"[^"\r\n]{0,48}(password|passcode)/ ascii wide nocase
        $net1 = "XMLHttp" ascii wide nocase
        $net2 = "WinHttpRequest" ascii wide nocase
        $net3 = "Outlook.Application" ascii wide nocase
        $send = /\.[ \t]*Send\b/ ascii wide nocase

    condition:
        $prompt and any of ($net*) and $send
}

rule Office_VBA_WebhookWithSend : vba exfiltration
{
    meta:
        id = "OFM-VBA-1003"
        description = "Named messaging webhook endpoint pattern with HTTP client and Send member."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "exfiltration"
        subcategory = "webhooks"
        severity = "high"
        confidence = "medium"
        false_positive = "An approved macro may publish workflow notifications."
        attack = "T1567.004"

    strings:
        $dest1 = "discord.com/api/webhooks/" ascii wide nocase
        $dest2 = "hooks.slack.com/services/" ascii wide nocase
        $dest3 = "api.telegram.org/bot" ascii wide nocase
        $client1 = "XMLHTTP" ascii wide nocase
        $client2 = "WinHttpRequest" ascii wide nocase
        $send = /\.[ \t]*Send\b/ ascii wide nocase

    condition:
        any of ($dest*) and any of ($client*) and $send
}

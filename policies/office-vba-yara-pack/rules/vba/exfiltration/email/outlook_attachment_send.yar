rule Office_VBA_OutlookAttachmentSend : vba exfiltration
{
    meta:
        id = "OFM-VBA-1002"
        description = "Outlook automation with mail item creation, attachment addition and Send."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "exfiltration"
        subcategory = "email"
        severity = "high"
        confidence = "medium"
        false_positive = "Business reports and invoicing often automate Outlook attachments."

    strings:
        $outlook = "Outlook.Application" ascii wide nocase
        $item = /\.[ \t]*CreateItem[ \t(]+(olMailItem|0)\b/ ascii wide nocase
        $attachment = /\bAttachments[ \t]*\.[ \t]*Add\b/ ascii wide nocase
        $send = /\.[ \t]*Send\b/ ascii wide nocase

    condition:
        all of them
}

rule Office_VBA_ClipboardRead : vba collection
{
    meta:
        id = "OFM-VBA-1501"
        description = "Clipboard API trio or MSForms data object clipboard read pattern."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "collection"
        subcategory = "clipboard_and_keys"
        severity = "medium"
        confidence = "medium"
        false_positive = "Routine copy, paste and document formatting workflows can read clipboard data."
        attack = "T1115"

    strings:
        $api1 = "OpenClipboard" ascii wide nocase
        $api2 = "GetClipboardData" ascii wide nocase
        $api3 = "CloseClipboard" ascii wide nocase
        $form1 = "MSForms.DataObject" ascii wide nocase
        $form2 = /\bGetFromClipboard\b/ ascii wide nocase
        $form3 = /\.[ \t]*GetText\b/ ascii wide nocase

    condition:
        all of ($api*) or all of ($form*)
}

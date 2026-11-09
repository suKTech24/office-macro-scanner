rule Office_VBA_KeyStateAndCaptureLoop : vba collection
{
    meta:
        id = "OFM-VBA-1502"
        description = "Key state polling or Windows hook API paired with a loop or hook constant."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "collection"
        subcategory = "clipboard_and_keys"
        severity = "high"
        confidence = "medium"
        false_positive = "Accessibility tools and approved hotkey integrations may poll keys."
        attack = "T1056.001"

    strings:
        $poll1 = "GetAsyncKeyState" ascii wide nocase
        $poll2 = "SetWindowsHookEx" ascii wide nocase
        $context1 = "WH_KEYBOARD_LL" ascii wide nocase
        $context2 = /\bDo[ \t]+(While|Until)\b/ ascii wide nocase
        $context3 = /\bFor[ \t]+[A-Za-z_][A-Za-z_0-9]{0,24}[ \t]*=/ ascii wide nocase

    condition:
        any of ($poll*) and any of ($context*)
}

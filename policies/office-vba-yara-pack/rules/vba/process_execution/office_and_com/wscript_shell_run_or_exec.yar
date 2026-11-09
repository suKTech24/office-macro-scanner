rule Office_VBA_WScriptShellRunOrExec : vba process_execution
{
    meta:
        id = "OFM-VBA-0302"
        description = "WScript.Shell automation class with a Run or Exec member."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "process_execution"
        subcategory = "office_and_com"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved line-of-business integrations sometimes launch local tools."
        attack = "T1059.005"

    strings:
        $class = "WScript.Shell" ascii wide nocase
        $method = /\.[ \t]*(Run|Exec)[ \t(]/ ascii wide nocase

    condition:
        all of them
}

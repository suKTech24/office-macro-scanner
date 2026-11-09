rule Office_VBA_ShellApplicationLaunch : vba process_execution
{
    meta:
        id = "OFM-VBA-0305"
        description = "Shell.Application automation class and ShellExecute member."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "process_execution"
        subcategory = "office_and_com"
        severity = "medium"
        confidence = "medium"
        false_positive = "Normal file association and desktop integration helpers."

    strings:
        $class = "Shell.Application" ascii wide nocase
        $method = /\.[ \t]*ShellExecute[ \t(]/ ascii wide nocase

    condition:
        all of them
}

rule Office_VBA_ExecutableWriteToUserLocation : vba file_operations
{
    meta:
        id = "OFM-VBA-0701"
        description = "File write primitive paired with a user-writable location and executable or script suffix."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "file_operations"
        subcategory = "writes"
        severity = "high"
        confidence = "medium"
        false_positive = "An approved add-in installer or updater may stage executable helpers."

    strings:
        $write1 = "SaveToFile" ascii wide nocase
        $write2 = /\bFor[ \t]+(Binary|Output)[ \t]+(Access[ \t]+Write[ \t]+)?As[ \t]+#/ ascii wide nocase
        $write3 = "CreateTextFile" ascii wide nocase
        $path1 = /Environ\$?[ \t]*\([ \t]*"(TEMP|TMP|APPDATA|LOCALAPPDATA)"/ ascii wide nocase
        $path2 = "%TEMP%" ascii wide nocase
        $path3 = "\\AppData\\Local\\Temp\\" ascii wide nocase
        $suffix = /\.(exe|dll|ps1|vbs|js|hta|bat|cmd|scr)\b/ ascii wide nocase

    condition:
        any of ($write*) and any of ($path*) and $suffix
}

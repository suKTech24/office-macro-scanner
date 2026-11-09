rule Office_VBA_NativeProcessApiDeclaration : vba process_execution
{
    meta:
        id = "OFM-VBA-0303"
        description = "VBA declares a native Windows process-launch API."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "process_execution"
        subcategory = "native_launch"
        severity = "medium"
        confidence = "medium"
        false_positive = "Legitimate add-ins may declare native process helpers."
        attack = "T1059.005"

    strings:
        $decl = /\bDeclare[ \t]+(PtrSafe[ \t]+)?(Function|Sub)[ \t]+(CreateProcess[AW]?|ShellExecute(Ex)?[AW]?|WinExec)\b/ ascii wide nocase
        $alias = /\bAlias[ \t]+"(CreateProcess[AW]?|ShellExecute(Ex)?[AW]?|WinExec)"/ ascii wide nocase
        $lib1 = "kernel32" ascii wide nocase
        $lib2 = "shell32" ascii wide nocase

    condition:
        ($decl or $alias) and any of ($lib*)
}

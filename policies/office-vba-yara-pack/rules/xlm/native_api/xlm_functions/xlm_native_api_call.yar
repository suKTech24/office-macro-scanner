rule Office_XLM_XlmNativeApiCall : xlm native_api
{
    meta:
        id = "OFM-XLM-0401"
        description = "Excel 4.0 CALL or REGISTER formula paired with an execution, download or memory API."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "xlm"
        category = "native_api"
        subcategory = "xlm_functions"
        severity = "high"
        confidence = "medium"
        false_positive = "Legacy financial and engineering models can call native libraries."
        attack = "T1105"

    strings:
        $func = /\b(CALL|REGISTER)[ \t]*\(/ ascii wide nocase
        $api1 = "URLDownloadToFile" ascii wide nocase
        $api2 = "ShellExecute" ascii wide nocase
        $api3 = "CreateProcess" ascii wide nocase
        $api4 = "VirtualAlloc" ascii wide nocase
        $api5 = "WriteProcessMemory" ascii wide nocase

    condition:
        $func and any of ($api*)
}

rule Office_XLM_XlmDownloadAndExec : xlm execution_chains
{
    meta:
        id = "OFM-XLM-1601"
        description = "XLM native download API marker combined with EXEC formula."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "xlm"
        category = "execution_chains"
        subcategory = "download_and_execute"
        severity = "high"
        confidence = "high"
        false_positive = "A legacy updater can download and launch an approved helper."
        attack = "T1105,T1059"

    strings:
        $download = "URLDownloadToFile" ascii wide nocase
        $exec = /\bEXEC[ \t]*\(/ ascii wide nocase

    condition:
        all of them
}

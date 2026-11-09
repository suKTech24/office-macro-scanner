rule Office_XML_DdeCommandInterpreter : office_xml external_content
{
    meta:
        id = "OFM-XML-1903"
        description = "One decoded field instruction contains DDE or DDEAUTO and a command interpreter or script host."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "office_xml"
        category = "external_content"
        subcategory = "fields"
        severity = "high"
        confidence = "high"
        false_positive = "Approved legacy DDE workflows may reference command-line helpers."

    strings:
        $dde = /\bDDE(AUTO)?[ \t]/ ascii wide nocase
        $tool1 = /\bcmd(\.exe)?[ \t"]/ ascii wide nocase
        $tool2 = "powershell" ascii wide nocase
        $tool3 = "mshta" ascii wide nocase
        $tool4 = "wscript.exe" ascii wide nocase

    condition:
        $dde and any of ($tool*)
}

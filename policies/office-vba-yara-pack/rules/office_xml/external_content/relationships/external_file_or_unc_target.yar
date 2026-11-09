rule Office_XML_ExternalFileOrUncTarget : office_xml external_content
{
    meta:
        id = "OFM-XML-1904"
        description = "An external OOXML relationship has a file URI or literal UNC target."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "office_xml"
        category = "external_content"
        subcategory = "relationships"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved templates and documents can link to internal shared drives."

    strings:
        $mode = /\bTargetMode\s*=\s*["']External["']/ ascii wide nocase
        $target = /\bTarget\s*=\s*["'](file:\/\/|\\\\)/ ascii wide nocase

    condition:
        all of them
}

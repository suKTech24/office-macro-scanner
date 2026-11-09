rule Office_XML_ExternalAttachedTemplate : office_xml external_content
{
    meta:
        id = "OFM-XML-1901"
        description = "One OOXML relationship references an external attached template."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "office_xml"
        category = "external_content"
        subcategory = "relationships"
        severity = "high"
        confidence = "medium"
        false_positive = "Corporate Word documents may use approved centrally hosted templates."
        attack = "T1221"

    strings:
        $mode = /\bTargetMode\s*=\s*["']External["']/ ascii wide nocase
        $type = /\bType\s*=\s*["'][^"'<>]{0,180}\/attachedTemplate["']/ ascii wide nocase

    condition:
        all of them
}

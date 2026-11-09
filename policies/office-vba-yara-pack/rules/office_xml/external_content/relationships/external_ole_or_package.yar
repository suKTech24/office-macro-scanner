rule Office_XML_ExternalOleOrPackage : office_xml external_content
{
    meta:
        id = "OFM-XML-1902"
        description = "One OOXML relationship references an external OLE object or package."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "office_xml"
        category = "external_content"
        subcategory = "relationships"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved linked OLE objects can reference a managed network location."

    strings:
        $mode = /\bTargetMode\s*=\s*["']External["']/ ascii wide nocase
        $type = /\bType\s*=\s*["'][^"'<>]{0,180}\/(oleObject|package)["']/ ascii wide nocase

    condition:
        all of them
}

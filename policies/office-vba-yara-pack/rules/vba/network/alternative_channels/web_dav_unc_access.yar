rule Office_VBA_WebDavUncAccess : vba network
{
    meta:
        id = "OFM-VBA-0805"
        description = "UNC WebDAV path marker paired with a file or shell access primitive."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "network"
        subcategory = "alternative_channels"
        severity = "medium"
        confidence = "medium"
        false_positive = "Organisations may use approved WebDAV or SharePoint integrations."

    strings:
        $dav1 = "@SSL\\DavWWWRoot" ascii wide nocase
        $dav2 = "\\DavWWWRoot\\" ascii wide nocase
        $access1 = "OpenTextFile" ascii wide nocase
        $access2 = "CopyFile" ascii wide nocase
        $access3 = "ShellExecute" ascii wide nocase

    condition:
        any of ($dav*) and any of ($access*)
}

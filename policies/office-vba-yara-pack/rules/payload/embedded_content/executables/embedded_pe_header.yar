rule Office_PAY_EmbeddedPeHeader : payload embedded_content
{
    meta:
        id = "OFM-PAY-2001"
        description = "A separately extracted object begins with MZ and a PE header at the declared offset."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "payload"
        category = "embedded_content"
        subcategory = "executables"
        severity = "high"
        confidence = "medium"
        false_positive = "A packaged installer or support executable can be legitimate."

    condition:
        filesize >= 68 and uint16(0) == 0x5a4d
        and uint32(0x3c) >= 64 and uint32(0x3c) <= filesize - 4
        and uint32(uint32(0x3c)) == 0x00004550
}

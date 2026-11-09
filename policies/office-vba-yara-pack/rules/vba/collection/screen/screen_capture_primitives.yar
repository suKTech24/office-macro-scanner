rule Office_VBA_ScreenCapturePrimitives : vba collection
{
    meta:
        id = "OFM-VBA-1503"
        description = "Screen or display context, BitBlt, and a bitmap export or screen metrics marker."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "collection"
        subcategory = "screen"
        severity = "high"
        confidence = "medium"
        false_positive = "Approved report automation and accessibility macros may capture screenshots."
        attack = "T1113"

    strings:
        $copy = "BitBlt" ascii wide nocase
        $source1 = "GetDesktopWindow" ascii wide nocase
        $source2 = /\bGetDC[ \t]*\([ \t]*0[ \t]*\)/ ascii wide nocase
        $result1 = "GetDIBits" ascii wide nocase
        $result2 = "GetSystemMetrics" ascii wide nocase
        $result3 = "SavePicture" ascii wide nocase

    condition:
        $copy and any of ($source*) and any of ($result*)
}

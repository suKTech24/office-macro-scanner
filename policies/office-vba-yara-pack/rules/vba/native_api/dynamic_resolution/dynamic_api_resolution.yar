rule Office_VBA_DynamicApiResolution : vba native_api
{
    meta:
        id = "OFM-VBA-0404"
        description = "Dynamic library loading and exported function lookup."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "native_api"
        subcategory = "dynamic_resolution"
        severity = "medium"
        confidence = "medium"
        false_positive = "Compatibility wrappers can load optional DLL functions."
        attack = "T1027.007"

    strings:
        $load1 = "LoadLibrary" ascii wide nocase
        $load2 = "LdrLoadDll" ascii wide nocase
        $get1 = "GetProcAddress" ascii wide nocase
        $get2 = "LdrGetProcedureAddress" ascii wide nocase

    condition:
        any of ($load*) and any of ($get*)
}

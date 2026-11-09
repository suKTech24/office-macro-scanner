rule Office_PCD_PcodeNetworkWriteAndLaunch : pcode execution_chains
{
    meta:
        id = "OFM-PCD-1601"
        description = "P-code HTTP and binary response markers, SaveToFile and a launch opcode."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "pcode"
        category = "execution_chains"
        subcategory = "download_and_execute"
        severity = "high"
        confidence = "high"
        false_positive = "Approved VBA updaters may download and launch a helper."
        attack = "T1105,T1059.005"

    strings:
        $client1 = "XMLHTTP" ascii wide nocase
        $client2 = "WinHttpRequest" ascii wide nocase
        $response = /\b(MemLd|MemLdWith)[ \t]+ResponseBody\b/ ascii wide nocase
        $save = /\b(ArgsMemCall|ArgsMemCallWith)[ \t]+(\(Call\)[ \t]+)?SaveToFile\b/ ascii wide nocase
        $launch1 = /\b(ArgsCall|ArgsLd)[ \t]+(\(Call\)[ \t]+)?Shell[ \t]+0x[0-9a-f]{4}\b/ ascii wide nocase
        $launch2 = /\b(ArgsMemCall|ArgsMemCallWith)[ \t]+(\(Call\)[ \t]+)?ShellExecute\b/ ascii wide nocase

    condition:
        any of ($client*) and $response and $save and any of ($launch*)
}

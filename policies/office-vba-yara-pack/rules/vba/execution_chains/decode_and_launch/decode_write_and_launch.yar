rule Office_VBA_DecodeWriteAndLaunch : vba execution_chains
{
    meta:
        id = "OFM-VBA-1604"
        description = "Base64 decode marker, file write and a process launcher in the same artifact."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "vba"
        category = "execution_chains"
        subcategory = "decode_and_launch"
        severity = "high"
        confidence = "high"
        false_positive = "A signed installer or deployer might unpack a bundled executable."
        attack = "T1140,T1059.005"

    strings:
        $decode1 = "CryptStringToBinary" ascii wide nocase
        $decode2 = "NodeTypedValue" ascii wide nocase
        $write1 = "SaveToFile" ascii wide nocase
        $write2 = "CreateTextFile" ascii wide nocase
        $launch1 = /\bShell[ \t(]/ ascii wide nocase
        $launch2 = /\.[ \t]*Run[ \t(]/ ascii wide nocase
        $launch3 = "ShellExecute" ascii wide nocase

    condition:
        any of ($decode*) and any of ($write*) and any of ($launch*)
}

rule Office_PCD_PcodeShellOpcode : pcode command_execution
{
    meta:
        id = "OFM-PCD-0201"
        description = "P-code disassembly includes a VBA Shell invocation opcode."
        version = "1.0.0"
        updated = "2026-11-09"
        artifact = "pcode"
        category = "command_execution"
        subcategory = "process_launch"
        severity = "medium"
        confidence = "medium"
        false_positive = "Approved VBA may start local helper applications."
        attack = "T1059.005"

    strings:
        $call = /\b(ArgsCall|ArgsLd)[ \t]+(\(Call\)[ \t]+)?Shell[ \t]+0x[0-9a-f]{4}\b/ ascii wide nocase

    condition:
        $call
}

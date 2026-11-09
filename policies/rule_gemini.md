# Yara rule set

An prod-grade, modular repository structure for static triage of Microsoft Office documents (OLE/Compound File Binary Format and OOXML/ZIP packages) is organized below into categorized YARA rules.

----

### Repository Layout

```text
maldoc-yara-suite/
├── README.md
├── index.yar
└── rules/
    ├── auto_execution/
    │   └── auto_exec_triggers.yar
    ├── command_execution/
    │   └── shell_execution.yar
    ├── credential_access/
    │   └── credential_dumping.yar
    ├── defense_evasion/
    │   ├── vba_stomping.yar
    │   └── suspicious_apis.yar
    ├── file_operations/
    │   └── file_drop_and_write.yar
    ├── network/
    │   └── network_and_download.yar
    ├── obfuscation/
    │   └── code_obfuscation.yar
    ├── persistence/
    │   └── persistence_mechanisms.yar
    ├── process_execution/
    │   └── process_injection.yar
    └── registry/
        └── registry_modifications.yar

```

---

### Root Configuration

#### `README.md`

```markdown
# Malicious Office Document & VBA YARA Ruleset

Comprehensive static analysis YARA signatures designed to identify weaponized Microsoft Office files (Legacy OLE `.doc`/`.xls` and OOXML `.docm`/`.xlsm`).

## Taxonomy & Structure
The rules are split into threat categories mapped to the MITRE ATT&CK framework:
- `auto_execution`: Auto-run triggers and document hooks
- `command_execution`: CLI spawners, command interpreters, and script hosts
- `credential_access`: LSASS targeting, token/ticket staging, and DPAPI artifacts
- `defense_evasion`: VBA stomping, memory patching, and AMSI bypasses
- `file_operations`: Payload dropping, extraction, and staging to disk
- `network`: Web requests, downloaders, and remote template injection
- `obfuscation`: Encoding layers, char-building, and high-entropy macro structures
- `persistence`: Scheduled tasks, Startup staging, and Office Add-in abuse
- `process_execution`: Direct Windows API execution, hollowers, and memory loaders
- `registry`: Security setting modifications and COM hijacked keys

## Usage
Compile and run against target directory:
```bash
yara -r index.yar /path/to/target_samples/

```

```

#### `index.yar`
```yara
/*
   Master Index Include File
*/

include "rules/auto_execution/auto_exec_triggers.yar"
include "rules/command_execution/shell_execution.yar"
include "rules/credential_access/credential_dumping.yar"
include "rules/defense_evasion/vba_stomping.yar"
include "rules/defense_evasion/suspicious_apis.yar"
include "rules/file_operations/file_drop_and_write.yar"
include "rules/network/network_and_download.yar"
include "rules/obfuscation/code_obfuscation.yar"
include "rules/persistence/persistence_mechanisms.yar"
include "rules/process_execution/process_injection.yar"
include "rules/registry/registry_modifications.yar"

```

---

### Category Rule Files

#### 1. Auto Execution Triggers

`rules/auto_execution/auto_exec_triggers.yar`

```yara
rule Suspicious_Macro_AutoExecution_Triggers {
    meta:
        description = "Detects common auto-execution hooks in legacy OLE and OpenXML Office macros"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1204.002"
        severity = "MEDIUM"
        file_type = "OLE, OOXML"
    strings:
        // OLE and ZIP signatures
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // Document Open Hooks
        $hook_open1 = "AutoOpen" nocase ascii wide
        $hook_open2 = "Auto_Open" nocase ascii wide
        $hook_open3 = "Document_Open" nocase ascii wide
        $hook_open4 = "Workbook_Open" nocase ascii wide
        $hook_open5 = "AutoExec" nocase ascii wide
        $hook_open6 = "Auto_Exec" nocase ascii wide

        // Document Close/Exit Hooks
        $hook_close1 = "AutoClose" nocase ascii wide
        $hook_close2 = "Auto_Close" nocase ascii wide
        $hook_close3 = "Document_Close" nocase ascii wide
        $hook_close4 = "Workbook_BeforeClose" nocase ascii wide
        $hook_close5 = "AutoExit" nocase ascii wide

        // ActiveX & Form Interaction Triggers
        $hook_event1 = "UserForm_Initialize" nocase ascii wide
        $hook_event2 = "UserForm_Activate" nocase ascii wide
        $hook_event3 = "Document_BeforeClose" nocase ascii wide
        $hook_event4 = "InkPicture1_Painted" nocase ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        1 of ($hook_open*) or 1 of ($hook_close*) or 1 of ($hook_event*)
}

```

#### 2. Command Execution

`rules/command_execution/shell_execution.yar`

```yara
rule Suspicious_VBA_Command_Execution {
    meta:
        description = "Detects CLI invocation, script hosts, and shell spawning via Office macros"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1059.005"
        severity = "HIGH"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // Standard VBA Execution APIs
        $exec1 = "Shell(" nocase ascii wide
        $exec2 = "WScript.Shell" nocase ascii wide
        $exec3 = "Shell.Application" nocase ascii wide
        $exec4 = ".Run" nocase ascii wide
        $exec5 = ".Exec" nocase ascii wide
        $exec6 = "MacScript" nocase ascii wide

        // Command Interpreters
        $target1 = "powershell" nocase ascii wide
        $target2 = "pwsh" nocase ascii wide
        $target3 = "cmd.exe" nocase ascii wide
        $target4 = "mshta" nocase ascii wide
        $target5 = "cscript" nocase ascii wide
        $target6 = "wscript" nocase ascii wide
        $target7 = "rundll32" nocase ascii wide
        $target8 = "regsvr32" nocase ascii wide
        $target9 = "certutil" nocase ascii wide
        $target10 = "bitsadmin" nocase ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        1 of ($exec*) and 1 of ($target*)
}

```

#### 3. Credential Access

`rules/credential_access/credential_dumping.yar`

```yara
rule Malicious_Document_Credential_Access {
    meta:
        description = "Detects credential-theft artifacts and memory-dumping strings inside Office files"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1003"
        severity = "CRITICAL"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // Process targeting
        $cred1 = "lsass" nocase ascii wide
        $cred2 = "MiniDumpWriteDump" ascii wide
        $cred3 = "Sekurlsa" nocase ascii wide
        $cred4 = "logonpasswords" nocase ascii wide
        $cred5 = "VaultCli" nocase ascii wide
        $cred6 = "samlib.dll" nocase ascii wide
        $cred7 = "SECURITY\\SAM" nocase ascii wide
        $cred8 = "ntdsutil" nocase ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        2 of ($cred*)
}

```

#### 4. Defense Evasion: VBA Stomping

`rules/defense_evasion/vba_stomping.yar`

```yara
rule VBA_Stomping_Compiled_Code_Artifacts {
    meta:
        description = "Detects potential VBA stomping indicators where compiled P-code exists without matching source code markers"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1564.007"
        severity = "HIGH"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // P-Code compiled VBA signatures & stream markers
        $pcode_dir   = "dir" ascii
        $pcode_proj  = "_VBA_PROJECT" ascii wide
        $vba_sub     = "Attribut" ascii wide

        // OLE Stream header for compressed source code
        $compressed_header = { 01 [2] 01 00 }

        // Stomping indicators: common P-code opcodes/signatures absent normal clean token declarations
        $pcode_op1 = { 4D 65 67 61 74 6F 6B 65 6E } // Megatoken
        $pcode_op2 = "StdOle" ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        $pcode_proj and ($pcode_dir or $pcode_op2) and
        not ($vba_sub)
}

```

#### 5. Defense Evasion: Suspicious APIs

`rules/defense_evasion/suspicious_apis.yar`

```yara
rule Suspicious_Office_VBA_Declare_APIs {
    meta:
        description = "Detects native Windows API bindings in VBA used for hooking, anti-analysis, or patch-bypasses"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1055, T1562.001"
        severity = "HIGH"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        $decl1 = "Declare PtrSafe Function" nocase ascii wide
        $decl2 = "Declare Function" nocase ascii wide

        // Evasion & Memory APIs
        $api1 = "VirtualAlloc" ascii wide
        $api2 = "VirtualProtect" ascii wide
        $api3 = "RtlMoveMemory" ascii wide
        $api4 = "WriteProcessMemory" ascii wide
        $api5 = "CreateRemoteThread" ascii wide
        $api6 = "QueueUserAPC" ascii wide
        $api7 = "SetWindowsHookEx" ascii wide
        $api8 = "IsDebuggerPresent" ascii wide
        $api9 = "AmsiScanBuffer" ascii wide
        $api10 = "EtwEventWrite" ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        1 of ($decl*) and 1 of ($api*)
}

```

#### 6. File Operations & Dropping

`rules/file_operations/file_drop_and_write.yar`

```yara
rule Suspicious_Macro_File_Dropping {
    meta:
        description = "Detects file drop, stream-writing, and executable payload reconstruction via VBA"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1105"
        severity = "MEDIUM"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // File stream operations
        $stream1 = "ADODB.Stream" nocase ascii wide
        $stream2 = "Scripting.FileSystemObject" nocase ascii wide
        $stream3 = "Open " nocase ascii wide
        $stream4 = "For Binary" nocase ascii wide
        $stream5 = "SaveToFile" nocase ascii wide

        // Write targets
        $dir1 = "Environ(\"APPDATA\")" nocase ascii wide
        $dir2 = "Environ(\"TEMP\")" nocase ascii wide
        $dir3 = "Environ(\"TMP\")" nocase ascii wide
        $dir4 = "Environ(\"PROGRAMDATA\")" nocase ascii wide
        $dir5 = "Environ(\"USERPROFILE\")" nocase ascii wide
        $dir6 = "\\AppData\\" nocase ascii wide
        $dir7 = "\\Startup\\" nocase ascii wide

        // Executable extensions
        $ext1 = ".exe" nocase ascii wide
        $ext2 = ".dll" nocase ascii wide
        $ext3 = ".vbs" nocase ascii wide
        $ext4 = ".ps1" nocase ascii wide
        $ext5 = ".bat" nocase ascii wide
        $ext6 = ".hta" nocase ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        2 of ($stream*) and 1 of ($dir*) and 1 of ($ext*)
}

```

#### 7. Network & Remote Template Injection

`rules/network/network_and_download.yar`

```yara
rule Office_Network_Download_And_Template_Injection {
    meta:
        description = "Identifies remote resource retrieval through XMLHTTP, MSXML2, WinHttp, and OOXML TargetMode template injection"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1190, T1221"
        severity = "HIGH"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // HTTP/Download COM Objects
        $net1 = "MSXML2.XMLHTTP" nocase ascii wide
        $net2 = "MSXML2.ServerXMLHTTP" nocase ascii wide
        $net3 = "WinHttp.WinHttpRequest" nocase ascii wide
        $net4 = "Microsoft.XMLHTTP" nocase ascii wide
        $net5 = "URLDownloadToFile" nocase ascii wide
        $net6 = "InternetOpen" nocase ascii wide

        // Protocol indicators
        $proto1 = "http://" nocase ascii wide
        $proto2 = "https://" nocase ascii wide
        $proto3 = "ftp://" nocase ascii wide

        // Remote Template Injection (OOXML relationship target)
        $rel_target = "TargetMode=\"External\"" ascii
        $dotm_target = ".dotm" nocase ascii
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        (
            (1 of ($net*) and 1 of ($proto*)) or
            ($magic_zip at 0 and $rel_target and $dotm_target)
        )
}

```

#### 8. Code Obfuscation

`rules/obfuscation/code_obfuscation.yar`

```yara
rule Office_Macro_Obfuscation_Patterns {
    meta:
        description = "Detects obfuscation layers including dynamic evaluation, character concatenation loops, and base64 strings"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1027"
        severity = "MEDIUM"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // String decoders and dynamic execution
        $fn1 = "Chr(" nocase ascii wide
        $fn2 = "ChrW(" nocase ascii wide
        $fn3 = "ChrB(" nocase ascii wide
        $fn4 = "Replace(" nocase ascii wide
        $fn5 = "StrReverse(" nocase ascii wide
        $fn6 = "Xor" ascii wide
        $fn7 = "CallByName" nocase ascii wide

        // Hex & Base64 indicators in commands
        $b64_ps1 = "-enc" nocase ascii wide
        $b64_ps2 = "-encodedcommand" nocase ascii wide
        $b64_ps3 = "FromBase64String" nocase ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        (
            (#fn1 + #fn2 + #fn3 > 15 and 1 of ($fn4, $fn5, $fn6)) or
            ($fn7 and 1 of ($fn1, $fn2, $fn4, $fn5)) or
            1 of ($b64_ps*)
        )
}

```

#### 9. Persistence

`rules/persistence/persistence_mechanisms.yar`

```yara
rule Office_Macro_Persistence_Mechanisms {
    meta:
        description = "Detects persistence setup such as scheduled tasks, service registrations, and Startup directory payloads"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1053, T1547"
        severity = "HIGH"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // Scheduled task creation
        $task1 = "schtasks" nocase ascii wide
        $task2 = "Schedule.Service" nocase ascii wide
        $task3 = "/create" nocase ascii wide

        // Startup Folder & Registry Run
        $startup1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp" nocase ascii wide
        $startup2 = "CurrentVersion\\Run" nocase ascii wide
        $startup3 = "CurrentVersion\\RunOnce" nocase ascii wide

        // Word / Excel Add-in persistence
        $addin1 = "STARTUP" nocase ascii wide
        $addin2 = "XLSTART" nocase ascii wide
        $addin3 = ".wll" nocase ascii wide
        $addin4 = ".xll" nocase ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        (
            ($task1 and $task3) or
            $task2 or
            1 of ($startup*) or
            (2 of ($addin*))
        )
}

```

#### 10. Process Execution & Injection

`rules/process_execution/process_injection.yar`

```yara
rule Office_Macro_Process_Injection {
    meta:
        description = "Detects shellcode loading, cross-process manipulation, and injection through VBA"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1055"
        severity = "CRITICAL"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        $mem1 = "OpenProcess" ascii wide
        $mem2 = "VirtualAllocEx" ascii wide
        $mem3 = "WriteProcessMemory" ascii wide
        $mem4 = "CreateRemoteThread" ascii wide
        $mem5 = "RtlMoveMemory" ascii wide
        $mem6 = "CallWindowProc" ascii wide

        // Shellcode byte sequences or inline array setups
        $sc_chunk = { 55 89 E5 83 EC } // Common 32-bit function prologue
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        (
            ($mem1 and $mem2 and $mem3 and $mem4) or
            ($mem5 and $mem6 and $sc_chunk)
        )
}

```

#### 11. Registry Modifications

`rules/registry/registry_modifications.yar`

```yara
rule Office_Macro_Registry_Tampering {
    meta:
        description = "Detects VBA altering Windows registry settings, Macro security zones, or Trust Center policies"
        author = "Detection Engineering"
        reference = "MITRE ATT&CK T1112, T1562.001"
        severity = "HIGH"
        file_type = "OLE, OOXML"
    strings:
        $magic_ole = { D0 CF 11 E0 A1 B1 1A E1 }
        $magic_zip = { 50 4B 03 04 }

        // Registry Writing Methods
        $wreg1 = "RegWrite" nocase ascii wide
        $wreg2 = "StdRegProv" nocase ascii wide
        $wreg3 = "CreateKey" nocase ascii wide
        $wreg4 = "SetStringValue" nocase ascii wide
        $wreg5 = "SetDWORDValue" nocase ascii wide

        // Sensitive registry paths targeted by maldocs
        $path1 = "Software\\Microsoft\\Office\\" nocase ascii wide
        $path2 = "Security\\VBAWarnings" nocase ascii wide
        $path3 = "Security\\AccessVBOM" nocase ascii wide
        $path4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones" nocase ascii wide
    condition:
        ($magic_ole at 0 or $magic_zip at 0) and
        filesize < 25MB and
        1 of ($wreg*) and 1 of ($path*)
}

```

---

### Deployment & Validation Steps

1. **Repository Generation**: Place each rule file into its designated subfolder and save `index.yar` in the root folder alongside `README.md`.
2. **Syntax Validation**: Run a syntax check across all rules prior to deployment:
```bash
yara -C index.yar

```


3. **Threshold Calibration**: Adjust occurrence counters (`#fn1 + #fn2...`) and file size caps (`filesize < 25MB`) to meet your specific pipeline latency and false-positive criteria.

Would you like a companion shell or Python setup script that automatically generates this folder tree and writes the files to disk?
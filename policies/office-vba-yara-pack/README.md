# Office VBA YARA rule pack

A static detection baseline for Microsoft Office submissions in `ms-office-macro-security-pipeline`. The pack contains **97 separately maintained YARA rules**. Each rule file contains its own metadata, strings where applicable, and condition. Use this README as the Gemini project entry point. For ChatGPT, start with [`.chatgpt`](.chatgpt).

## Folder layout

```text
office-vba-yara-pack/
  .chatgpt
  README.md
  policies/
    01-intake-and-extraction.md
    02-triage-and-signing.md
    03-rule-authoring.md
  rules/
    vba/
      command_execution/
        powershell/
          power_shell_encoded_command.yar
    pcode/
    xlm/
    office_xml/
    payload/
    parser_evidence/
  tools/scan.py
  tests/fixtures.json
  tests/test_rules.py
  requirements.txt
```

The archive includes this source directory and an offline Git bundle. After extracting it, run the following from the extraction directory to create a separate clone.

```sh
git clone office-vba-yara-pack.bundle office-vba-yara-pack-clone
```

## Scan extracted artifacts

Use Python 3.10 or later and install the pinned YARA binding from the repository root. Run the scanner on trusted staging paths for files produced by your extractor.

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python tools/scan.py --kind vba extracted/ThisWorkbook.cls extracted/Module1.bas
python tools/scan.py --kind pcode extracted/ThisWorkbook.pcode.txt
python tools/scan.py --kind xlm extracted/MacroSheet.xlm.txt
```

The three scan commands use illustrative paths. The test command runs the synthetic fixtures without Office installed.

Each invocation returns JSON with a scan status, match IDs, metadata and bounded offsets, without the matched byte contents. Exit code `0` means the supplied artifacts were scanned, including cases with findings. Exit code `2` means a scan or invocation failed. Evaluate policy against the JSON and the extractor coverage record. A successful scan with zero matches establishes only that the selected rules found no indicators in the supplied artifacts.

## Match the rules to the input

| Route | Scan this input |
| --- | --- |
| `vba` | One decoded VBA source module or separately labelled normalised copy. |
| `pcode` | One module's compatible text disassembly, for example pcodedmp output split by module. |
| `xlm` | One Excel 4.0 macro sheet's extracted formulas and canonical defined names. |
| `office_xml` | One parsed OOXML relationship element or one complete decoded field instruction. |
| `payload` | One extracted embedded file, script or object payload. |
| `parser_evidence` | One documented flag from the trusted parser adapter, in exact ASCII. |

Office containers need a format-aware extraction step. The scanner does not unpack Office files, compare VBA source to compiled instructions, run macros or apply the signing policy. The pack's VBA rules look for observable syntax and strings. Static co-occurrence cannot establish reachability, the order of operations, or that a transfer succeeded. Obfuscated and split-module behavior may require static reconstruction and cross-module review.

For the pipeline, unpack or parse the Office container, inventory executable surfaces, extract and diff VBA, scan each applicable artifact, correlate findings at document level, then apply the review and signing decision. Keep the original hash and artifact coverage available throughout. See the [intake and extraction policy](policies/01-intake-and-extraction.md), the [triage and signing policy](policies/02-triage-and-signing.md) and the [folder and rule authoring policy](policies/03-rule-authoring.md).

## Validation and references

Every rule has a synthetic positive fixture and a benign baseline for its input type. Selected cases also have targeted negative fixtures. Tests compile every rule on its own and in its routed rule group, check metadata and uniqueness, and exercise scanner routing and failures. The shipped fixtures are text or illustrative header bytes. Calibrate the proposed gate against representative internal Office documents and labelled samples before enabling production enforcement.

- [VirusTotal YARA rule syntax](https://github.com/VirusTotal/yara/blob/master/docs/writingrules.rst) and [YARA Python API](https://yara.readthedocs.io/en/stable/yarapython.html).
- [Microsoft VBA module stream specification](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba/c66b58a6-f8ba-4141-9382-0612abce9926), [olevba documentation](https://github.com/decalage2/oletools/blob/master/oletools/doc/olevba.md) and [pcodedmp](https://github.com/bontchev/pcodedmp).
- [Microsoft XLM runtime analysis](https://www.microsoft.com/en-us/security/blog/2021/03/03/xlm-amsi-new-runtime-defense-against-excel-4-0-macro-malware/) and [OOXML package relationship target modes](https://learn.microsoft.com/en-us/dotnet/api/system.io.packaging.packagerelationship.targetmode).
- [MITRE ATT&CK Visual Basic](https://attack.mitre.org/techniques/T1059/005/) and [Malicious File](https://attack.mitre.org/techniques/T1204/002/).

## Rule index

Open the linked rule for its full YARA metadata, strings and condition.

### vba (77)

| Rule | Category / subcategory | Severity / confidence | Detection |
| --- | --- | --- | --- |
| [OFM-VBA-0101](rules/vba/auto_execution/office_events/auto_open_events.yar) | auto_execution / office_events | info / medium | Office startup or document-open procedure declaration. |
| [OFM-VBA-0102](rules/vba/auto_execution/office_events/close_events.yar) | auto_execution / office_events | info / medium | Office close or exit procedure declaration. |
| [OFM-VBA-0103](rules/vba/auto_execution/callbacks/scheduled_office_callback.yar) | auto_execution / callbacks | info / medium | Excel or Word macro scheduling through an Office callback. |
| [OFM-VBA-0104](rules/vba/auto_execution/office_events/power_point_and_outlook_events.yar) | auto_execution / office_events | info / medium | PowerPoint presentation-open or Outlook startup event declaration. |
| [OFM-VBA-0201](rules/vba/command_execution/powershell/power_shell_encoded_command.yar) | command_execution / powershell | high / high | PowerShell command text together with an encoded-command switch. |
| [OFM-VBA-0202](rules/vba/command_execution/powershell/power_shell_download_and_eval.yar) | command_execution / powershell | high / high | PowerShell network retrieval combined with an expression or script evaluation primitive. |
| [OFM-VBA-0203](rules/vba/command_execution/shell/windows_command_interpreter.yar) | command_execution / shell | medium / medium | A process-launch surface paired with cmd.exe /c or /k. |
| [OFM-VBA-0204](rules/vba/command_execution/script_hosts/script_host_with_vba_launcher.yar) | command_execution / script_hosts | medium / medium | VBScript, JScript or HTA host text paired with a process-launch surface. |
| [OFM-VBA-0205](rules/vba/command_execution/system_binaries/mshta_remote_or_inline.yar) | command_execution / system_binaries | high / high | Mshta paired with an HTTP URL or an inline scripting scheme. |
| [OFM-VBA-0206](rules/vba/command_execution/system_binaries/regsvr32_scriptlet.yar) | command_execution / system_binaries | high / high | Regsvr32 paired with scrobj and a scriptlet or an install switch. |
| [OFM-VBA-0207](rules/vba/command_execution/system_binaries/rundll32_script_or_writable_path.yar) | command_execution / system_binaries | high / medium | Rundll32 paired with an inline script marker or an explicit user-writable path marker. |
| [OFM-VBA-0301](rules/vba/process_execution/office_and_com/vba_shell_call.yar) | process_execution / office_and_com | medium / medium | VBA Shell call syntax outside a simple identifier substring. |
| [OFM-VBA-0302](rules/vba/process_execution/office_and_com/wscript_shell_run_or_exec.yar) | process_execution / office_and_com | medium / medium | WScript.Shell automation class with a Run or Exec member. |
| [OFM-VBA-0303](rules/vba/process_execution/native_launch/native_process_api_declaration.yar) | process_execution / native_launch | medium / medium | VBA declares a native Windows process-launch API. |
| [OFM-VBA-0304](rules/vba/process_execution/wmi/wmi_process_creation.yar) | process_execution / wmi | high / medium | WMI connection, Win32_Process and a process creation method appear in a module. |
| [OFM-VBA-0305](rules/vba/process_execution/office_and_com/shell_application_launch.yar) | process_execution / office_and_com | medium / medium | Shell.Application automation class and ShellExecute member. |
| [OFM-VBA-0306](rules/vba/process_execution/office_and_com/dynamic_dispatch_with_launcher.yar) | process_execution / office_and_com | high / medium | VBA dynamic dispatch combined with a process creation or script host marker. |
| [OFM-VBA-0401](rules/vba/native_api/process_injection/remote_thread_injection_chain.yar) | native_api / process_injection | high / high | Process access, remote memory write, and a remote thread creation primitive. |
| [OFM-VBA-0402](rules/vba/native_api/process_injection/apc_injection_chain.yar) | native_api / process_injection | high / high | Remote allocation and memory write paired with APC queueing. |
| [OFM-VBA-0403](rules/vba/native_api/memory_execution/in_process_memory_execution.yar) | native_api / memory_execution | high / high | Native memory allocation, byte copy and thread or callback execution markers. |
| [OFM-VBA-0404](rules/vba/native_api/dynamic_resolution/dynamic_api_resolution.yar) | native_api / dynamic_resolution | medium / medium | Dynamic library loading and exported function lookup. |
| [OFM-VBA-0405](rules/vba/native_api/memory_execution/process_hollowing_primitives.yar) | native_api / memory_execution | high / high | Suspended-process indicators combined with unmapping or thread-context manipulation and resumption. |
| [OFM-VBA-0501](rules/vba/credential_access/windows_stores/credential_manager_read.yar) | credential_access / windows_stores | high / medium | Credential retrieval or enumeration API associated with advapi32. |
| [OFM-VBA-0502](rules/vba/credential_access/browsers/browser_stores_and_dpapi.yar) | credential_access / browsers | high / high | Browser credential store indicators combined with a DPAPI decryption function. |
| [OFM-VBA-0503](rules/vba/credential_access/system_secrets/lsass_memory_access.yar) | credential_access / system_secrets | high / high | LSASS target text plus a dump or memory read function and a process handle marker. |
| [OFM-VBA-0504](rules/vba/credential_access/system_secrets/registry_hive_export.yar) | credential_access / system_secrets | high / high | reg.exe save command text paired with a protected Windows hive name. |
| [OFM-VBA-0505](rules/vba/credential_access/tokens_and_prompts/cloud_token_store_access.yar) | credential_access / tokens_and_prompts | high / medium | Cloud CLI or developer credential store text paired with a local file read primitive. |
| [OFM-VBA-0506](rules/vba/credential_access/tokens_and_prompts/password_prompt_and_outbound.yar) | credential_access / tokens_and_prompts | high / medium | A password-like input prompt paired with a network send or Outlook item send. |
| [OFM-VBA-0601](rules/vba/evasion/encoding/chr_string_construction.yar) | evasion / encoding | medium / medium | Repeated Chr or ChrW character construction alongside string concatenation. |
| [OFM-VBA-0602](rules/vba/evasion/encoding/base64_decoder_or_xml_typed_value.yar) | evasion / encoding | medium / medium | Base64 conversion API or MSXML typed value paired with a Base64 data type. |
| [OFM-VBA-0603](rules/vba/evasion/encoding/reversed_or_decomposed_strings.yar) | evasion / encoding | medium / medium | String reversal combined with string splitting or replacement. |
| [OFM-VBA-0604](rules/vba/evasion/environment_checks/debugger_and_vm_checks.yar) | evasion / environment_checks | medium / medium | Debugger probes or virtual-machine fingerprints combined with an environment-query marker. |
| [OFM-VBA-0605](rules/vba/evasion/environment_checks/delay_and_launch.yar) | evasion / environment_checks | medium / medium | Sleep API or time-based waiting logic together with a process-launch primitive. |
| [OFM-VBA-0606](rules/vba/evasion/concealment/hidden_process_launch.yar) | evasion / concealment | medium / medium | VBA process launch with a hidden-window hint. |
| [OFM-VBA-0607](rules/vba/evasion/concealment/hidden_file_attributes.yar) | evasion / concealment | medium / medium | File attribute modification using hidden or system flags. |
| [OFM-VBA-0701](rules/vba/file_operations/writes/executable_write_to_user_location.yar) | file_operations / writes | high / medium | File write primitive paired with a user-writable location and executable or script suffix. |
| [OFM-VBA-0702](rules/vba/file_operations/writes/adodb_stream_binary_save.yar) | file_operations / writes | medium / medium | ADODB.Stream binary body or binary stream type paired with SaveToFile. |
| [OFM-VBA-0703](rules/vba/file_operations/deletion/file_deletion.yar) | file_operations / deletion | medium / medium | Direct VBA file deletion or file-system automation deletion member. |
| [OFM-VBA-0704](rules/vba/file_operations/archives/archive_staging.yar) | file_operations / archives | medium / medium | Archive command text paired with an archive extension or compression mode and a process launcher. |
| [OFM-VBA-0705](rules/vba/file_operations/reads/sensitive_profile_file_read.yar) | file_operations / reads | medium / medium | Local file read paired with browser history, remote access configuration, or key file indicators. |
| [OFM-VBA-0801](rules/vba/network/http_clients/http_com_request.yar) | network / http_clients | medium / medium | Windows HTTP COM automation class with Open and Send members. |
| [OFM-VBA-0802](rules/vba/network/native_clients/url_download_api.yar) | network / native_clients | medium / medium | Native URLMon download function with a URLMon library marker. |
| [OFM-VBA-0803](rules/vba/network/native_clients/win_inet_or_win_http_api.yar) | network / native_clients | medium / medium | Native WinInet or WinHTTP API markers covering session setup and data transfer. |
| [OFM-VBA-0804](rules/vba/network/alternative_channels/dns_command_with_launcher.yar) | network / alternative_channels | medium / medium | DNS lookup utility or PowerShell DNS command combined with a launch surface. |
| [OFM-VBA-0805](rules/vba/network/alternative_channels/web_dav_unc_access.yar) | network / alternative_channels | medium / medium | UNC WebDAV path marker paired with a file or shell access primitive. |
| [OFM-VBA-0901](rules/vba/network_obfuscation/url_forms/numeric_http_host.yar) | network_obfuscation / url_forms | medium / medium | HTTP URL using a dotted numeric host or a single large decimal host. |
| [OFM-VBA-0902](rules/vba/network_obfuscation/url_forms/url_shortener_in_network_module.yar) | network_obfuscation / url_forms | medium / medium | Known short-link service text paired with VBA HTTP client or download primitives. |
| [OFM-VBA-0903](rules/vba/network_obfuscation/url_forms/split_or_reversed_http_scheme.yar) | network_obfuscation / url_forms | medium / medium | A split HTTP scheme or reversed scheme literal paired with networking primitives. |
| [OFM-VBA-1001](rules/vba/exfiltration/http_upload/http_post_with_file_or_document_read.yar) | exfiltration / http_upload | high / medium | HTTP POST or PUT and a send member combined with a file or document read marker. |
| [OFM-VBA-1002](rules/vba/exfiltration/email/outlook_attachment_send.yar) | exfiltration / email | high / medium | Outlook automation with mail item creation, attachment addition and Send. |
| [OFM-VBA-1003](rules/vba/exfiltration/webhooks/webhook_with_send.yar) | exfiltration / webhooks | high / medium | Named messaging webhook endpoint pattern with HTTP client and Send member. |
| [OFM-VBA-1004](rules/vba/exfiltration/command_tools/command_line_file_upload.yar) | exfiltration / command_tools | high / medium | Curl file upload or multipart file syntax with an HTTP destination and VBA process launcher. |
| [OFM-VBA-1101](rules/vba/persistence/office_startup/office_startup_path_write.yar) | persistence / office_startup | high / medium | Office startup location or template reference paired with a save or copy primitive. |
| [OFM-VBA-1102](rules/vba/persistence/vba_project/vba_project_modification.yar) | persistence / vba_project | high / medium | VBA project object access paired with source editing, module import or organiser copy. |
| [OFM-VBA-1103](rules/vba/persistence/windows_logon/startup_folder_write.yar) | persistence / windows_logon | high / medium | Windows Startup folder lookup or path paired with a file or shortcut write. |
| [OFM-VBA-1104](rules/vba/persistence/scheduled_tasks/scheduled_task_registration.yar) | persistence / scheduled_tasks | high / medium | Scheduled task creation through schtasks command text or Task Scheduler COM. |
| [OFM-VBA-1105](rules/vba/persistence/services/service_creation.yar) | persistence / services | high / medium | Windows service creation via command-line or native API declaration. |
| [OFM-VBA-1201](rules/vba/registry/modification/registry_write_or_delete.yar) | registry / modification | medium / medium | Registry modification via Windows Script Host, native API names or reg.exe command text. |
| [OFM-VBA-1202](rules/vba/registry/autoruns/run_key_write.yar) | registry / autoruns | high / medium | Windows Run or RunOnce registry path paired with a registry write primitive. |
| [OFM-VBA-1203](rules/vba/registry/autoruns/image_file_execution_options_write.yar) | registry / autoruns | high / high | IFEO registry path with Debugger or GlobalFlag marker and a registry write primitive. |
| [OFM-VBA-1204](rules/vba/registry/discovery/registry_read.yar) | registry / discovery | info / medium | Direct Windows Script Host registry read or native registry query API. |
| [OFM-VBA-1301](rules/vba/defense_impairment/office_security/office_trust_settings_write.yar) | defense_impairment / office_security | high / medium | Registry write combined with Office Security or Trusted Locations and a sensitive setting marker. |
| [OFM-VBA-1302](rules/vba/defense_impairment/endpoint_security/defender_disable_or_exclusion.yar) | defense_impairment / endpoint_security | high / high | Defender preference commands paired with disabling or exclusion arguments. |
| [OFM-VBA-1303](rules/vba/defense_impairment/endpoint_security/amsi_tamper_indicators.yar) | defense_impairment / endpoint_security | high / high | AMSI scan routine and memory protection or patch-related identifiers appear together. |
| [OFM-VBA-1304](rules/vba/defense_impairment/logging/windows_event_log_clear.yar) | defense_impairment / logging | high / high | Event log clearing command text or Clear-EventLog cmdlet. |
| [OFM-VBA-1401](rules/vba/discovery/host_inventory/wmi_host_discovery.yar) | discovery / host_inventory | info / medium | WMI connection text paired with OS, process or security product discovery classes. |
| [OFM-VBA-1402](rules/vba/discovery/host_inventory/host_discovery_commands.yar) | discovery / host_inventory | info / medium | Process launch text paired with at least two common host or network discovery commands. |
| [OFM-VBA-1501](rules/vba/collection/clipboard_and_keys/clipboard_read.yar) | collection / clipboard_and_keys | medium / medium | Clipboard API trio or MSForms data object clipboard read pattern. |
| [OFM-VBA-1502](rules/vba/collection/clipboard_and_keys/key_state_and_capture_loop.yar) | collection / clipboard_and_keys | high / medium | Key state polling or Windows hook API paired with a loop or hook constant. |
| [OFM-VBA-1503](rules/vba/collection/screen/screen_capture_primitives.yar) | collection / screen | high / medium | Screen or display context, BitBlt, and a bitmap export or screen metrics marker. |
| [OFM-VBA-1601](rules/vba/execution_chains/download_and_execute/http_write_and_launch.yar) | execution_chains / download_and_execute | high / high | HTTP retrieval, binary file write and a process launch primitive in the same artifact. |
| [OFM-VBA-1602](rules/vba/execution_chains/download_and_execute/url_mon_download_and_launch.yar) | execution_chains / download_and_execute | high / high | URLMon download API marker and process launcher in the same artifact. |
| [OFM-VBA-1603](rules/vba/execution_chains/auto_launch/startup_event_and_launcher.yar) | execution_chains / auto_launch | high / medium | Office auto-open declaration combined with a command or script host and launcher. |
| [OFM-VBA-1604](rules/vba/execution_chains/decode_and_launch/decode_write_and_launch.yar) | execution_chains / decode_and_launch | high / high | Base64 decode marker, file write and a process launcher in the same artifact. |
| [OFM-VBA-1701](rules/vba/macos/scripting/apple_script_shell_command.yar) | macos / scripting | high / medium | AppleScript invocation marker with shell-command text or a common shell path. |
| [OFM-VBA-1702](rules/vba/macos/scripting/mac_os_shell_download.yar) | macos / scripting | high / high | Mac-oriented shell or AppleScript marker and a curl or wget command with an HTTP URL. |
| [OFM-VBA-1703](rules/vba/macos/persistence/launch_agent_write.yar) | macos / persistence | high / medium | macOS launch agent or daemon path paired with plist or launchctl and a write or launch primitive. |

### pcode (5)

| Rule | Category / subcategory | Severity / confidence | Detection |
| --- | --- | --- | --- |
| [OFM-PCD-0201](rules/pcode/command_execution/process_launch/pcode_shell_opcode.yar) | command_execution / process_launch | medium / medium | P-code disassembly includes a VBA Shell invocation opcode. |
| [OFM-PCD-0401](rules/pcode/native_api/process_injection/pcode_remote_injection_markers.yar) | native_api / process_injection | high / high | P-code artifact contains process access, remote memory write and remote thread markers. |
| [OFM-PCD-1101](rules/pcode/persistence/vba_project/pcode_project_modification.yar) | persistence / vba_project | high / medium | P-code member loads for VBA project access and an edit or import opcode. |
| [OFM-PCD-1301](rules/pcode/defense_impairment/endpoint_security/pcode_amsi_memory_markers.yar) | defense_impairment / endpoint_security | high / high | P-code artifact contains AMSI scan entry points and memory patching API names. |
| [OFM-PCD-1601](rules/pcode/execution_chains/download_and_execute/pcode_network_write_and_launch.yar) | execution_chains / download_and_execute | high / high | P-code HTTP and binary response markers, SaveToFile and a launch opcode. |

### xlm (6)

| Rule | Category / subcategory | Severity / confidence | Detection |
| --- | --- | --- | --- |
| [OFM-XLM-0101](rules/xlm/auto_execution/defined_names/xlm_auto_defined_name.yar) | auto_execution / defined_names | info / medium | Extractor emits an Excel 4.0 macro-sheet auto-execution defined name. |
| [OFM-XLM-0201](rules/xlm/command_execution/xlm_functions/xlm_exec_command.yar) | command_execution / xlm_functions | high / medium | Excel 4.0 EXEC formula with a command interpreter or script-host marker. |
| [OFM-XLM-0401](rules/xlm/native_api/xlm_functions/xlm_native_api_call.yar) | native_api / xlm_functions | high / medium | Excel 4.0 CALL or REGISTER formula paired with an execution, download or memory API. |
| [OFM-XLM-0601](rules/xlm/evasion/encoding/xlm_char_construction_and_execution.yar) | evasion / encoding | high / medium | Repeated Excel 4.0 CHAR construction with EXEC or CALL. |
| [OFM-XLM-0701](rules/xlm/file_operations/xlm_functions/xlm_file_write.yar) | file_operations / xlm_functions | medium / medium | Excel 4.0 file-open formula together with a file-write formula. |
| [OFM-XLM-1601](rules/xlm/execution_chains/download_and_execute/xlm_download_and_exec.yar) | execution_chains / download_and_execute | high / high | XLM native download API marker combined with EXEC formula. |

### office_xml (4)

| Rule | Category / subcategory | Severity / confidence | Detection |
| --- | --- | --- | --- |
| [OFM-XML-1901](rules/office_xml/external_content/relationships/external_attached_template.yar) | external_content / relationships | high / medium | One OOXML relationship references an external attached template. |
| [OFM-XML-1902](rules/office_xml/external_content/relationships/external_ole_or_package.yar) | external_content / relationships | high / medium | One OOXML relationship references an external OLE object or package. |
| [OFM-XML-1903](rules/office_xml/external_content/fields/dde_command_interpreter.yar) | external_content / fields | high / high | One decoded field instruction contains DDE or DDEAUTO and a command interpreter or script host. |
| [OFM-XML-1904](rules/office_xml/external_content/relationships/external_file_or_unc_target.yar) | external_content / relationships | medium / medium | An external OOXML relationship has a file URI or literal UNC target. |

### payload (2)

| Rule | Category / subcategory | Severity / confidence | Detection |
| --- | --- | --- | --- |
| [OFM-PAY-2001](rules/payload/embedded_content/executables/embedded_pe_header.yar) | embedded_content / executables | high / medium | A separately extracted object begins with MZ and a PE header at the declared offset. |
| [OFM-PAY-2002](rules/payload/embedded_content/scripts/embedded_script_markers.yar) | embedded_content / scripts | high / medium | Standalone embedded text contains script-host or PowerShell markers and execution or download primitives. |

### parser_evidence (3)

| Rule | Category / subcategory | Severity / confidence | Detection |
| --- | --- | --- | --- |
| [OFM-EVD-1801](rules/parser_evidence/vba_integrity/source_pcode/stomping_suspected.yar) | vba_integrity / source_pcode | high / high | A trusted parser or adapter reports a suspected source and p-code mismatch. |
| [OFM-EVD-1802](rules/parser_evidence/vba_integrity/source_pcode/pcode_with_empty_source.yar) | vba_integrity / source_pcode | high / high | A trusted parser reports meaningful compiled VBA instructions with missing or empty source for the same module. |
| [OFM-EVD-1803](rules/parser_evidence/vba_integrity/coverage/vba_analysis_incomplete.yar) | vba_integrity / coverage | high / medium | A trusted parser reports a coverage failure on a VBA project requiring inspection. |

# M365 Defender Advanced hunting 
Plaso (log2timeline) - Parser for M365 Defender Advanced hunting export file

## About 

This is custom parser which allows add to timeline export of results from Advanced hunting at M365 Defender. That's why you can see some additional informations, which can provide better overview.

Parser is created for [Plaso (log2timeline)](https://plaso.readthedocs.io/en/latest/index.html "Plaso (log2timeline)") and it was tested with actually latest [release (20230717)](https://github.com/log2timeline/plaso/releases/tag/20230717 "release (20230717)").

## Implementation 

For implementation it's necesseary do four steps.

### 1) Parser 

Just copy parser **defender_hunting.py** to folder ***plaso/parsers/***.

### 2) Registering a parser

To ensure the parser is registered automatically add an import to file ***plaso/parsers/__init__.py***:

```
from plaso.parsers import defender_hunting
```

### 3) Timeliner

You can take content for adjust ***data/timeliner.yaml*** from [file](https://github.com/dafneb/defender_hunting/blob/main/data/timeliner.yaml "timeliner.yaml") or just copy text below.

```
---
data_type: 'defender:advanced_hunting:scancomplete'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:asrtheftaudited'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:connfailed'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:connsuccess'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:dnsinspected'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:icmpinspected'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:inconnaccept'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:listenconncreated'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:powershellcommand'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:processcreated'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:processcreatedwmi'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
---
data_type: 'defender:advanced_hunting:serviceinstalled'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
```

### 4) Formatter 

Just copy formatter **defender.yaml** to folder ***data/formatters/***.

## Usage 

### Required KQL 

For keep parser working, just use KQL mentioned below. Adjust name of the device and clikc on "Run query" button.

```
union DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents
| where DeviceName contains "<device>"
| where ActionType in (
    'AntivirusScanCompleted',
    'AsrLsassCredentialTheftAudited',
    'ConnectionFailed',
    'ConnectionSuccess',
    'DnsConnectionInspected',
    'IcmpConnectionInspected',
    'InboundConnectionAccepted',
    'ListeningConnectionCreated',
    'PowerShellCommand',
    'ProcessCreated',
    'ProcessCreatedUsingWmiQuery',
    'ServiceInstalled'
)
| project Timestamp,DeviceId,DeviceName,ActionType,FileName,FolderPath,SHA1,SHA256,MD5,FileSize,ProcessVersionInfoCompanyName,ProcessVersionInfoProductName,ProcessVersionInfoProductVersion,ProcessVersionInfoInternalFileName,ProcessVersionInfoOriginalFileName,ProcessVersionInfoFileDescription,ProcessId,ProcessCommandLine,ProcessIntegrityLevel,ProcessTokenElevation,ProcessCreationTime,AccountDomain,AccountName,AccountSid,AccountUpn,AccountObjectId,LogonId,InitiatingProcessAccountDomain,InitiatingProcessAccountName,InitiatingProcessAccountSid,InitiatingProcessAccountUpn,InitiatingProcessAccountObjectId,InitiatingProcessLogonId,InitiatingProcessIntegrityLevel,InitiatingProcessTokenElevation,InitiatingProcessSHA1,InitiatingProcessSHA256,InitiatingProcessMD5,InitiatingProcessFileName,InitiatingProcessFileSize,InitiatingProcessVersionInfoCompanyName,InitiatingProcessVersionInfoProductName,InitiatingProcessVersionInfoProductVersion,InitiatingProcessVersionInfoInternalFileName,InitiatingProcessVersionInfoOriginalFileName,InitiatingProcessVersionInfoFileDescription,InitiatingProcessId,InitiatingProcessCommandLine,InitiatingProcessCreationTime,InitiatingProcessFolderPath,InitiatingProcessParentId,InitiatingProcessParentFileName,InitiatingProcessParentCreationTime,InitiatingProcessSignerType,InitiatingProcessSignatureStatus,ReportId,AppGuardContainerId,AdditionalFields,RemoteIP,RemotePort,RemoteUrl,LocalIP,LocalPort,Protocol,LocalIPType,RemoteIPType,RemoteDeviceName,RegistryKey,RegistryValueName,RegistryValueData,FileOriginUrl,FileOriginIP
```

Then export results.

### Log2timeline / psort.py

If implementation was sucessfull, then use "defender_hunting" at parameter "--parsers".

Example:

```
log2timeline.py --single-process -z "UTC" --parsers "defender_hunting" --storage-file timeline.dump .
```

- - - -

> Note: Package also contains unittests module, example of export and example of results. You can find it at folder ***tests***.



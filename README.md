# M365 Defender Advanced hunting #
Plaso (log2timeline) - Parser for M365 Defender Advanced hunting export file

## About ##

## Implementation ##

### Parser ###

### Import of parser ###
```
from plaso.parsers import defender_hunting
```

### timeliner.yaml ###
```
---
data_type: 'defender:advanced_hunting:line'
attribute_mappings:
- name: 'timestamp'
  description: 'Timestamp'
place_holder_event: true
```

### Formatrer ###

## Required KQL ##

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


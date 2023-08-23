# USB Detection

### Description

USB attack and data exfiltration is one of the most attacks we face in cybersecurity, hence a lot of orgnisations restrict the use of usb devices. This Advanced hunting query for Microsoft Defender searches for the use of plug and play devices within your organisation.

### Microsoft 365 Defender
```
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| extend ParsedFields=parse_json(AdditionalFields)
| project ClassName=tostring(ParsedFields.ClassName), DeviceDescription=tostring(ParsedFields.DeviceDescription),
DeviceId=tostring(ParsedFields.DeviceId), VendorIds=tostring(ParsedFields.VendorIds), "MachineId", "ComputerName", "EventTime"
| where ClassName contains "drive" or ClassName contains "usb"
```

### MITRE ATT&CK Mapping
- Tactic: Collection
- Technique ID: T1025
- (https://attack.mitre.org/techniques/T1025/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 23/08/2023    | Initial publish                   |

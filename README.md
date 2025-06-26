# Threat Event (Unauthorized AnyDesk Usage)
Installation and Use of AnyDesk for Remote Access Without Authorization

Reason for the Hunt:
Unusual system behavior was reported on multiple endpoints, including sudden performance lag and clipboard access alerts.

Additionally, a cybersecurity news bulletin highlighted a recent phishing campaign using AnyDesk for lateral movement and persistence.
| **Parameter**           | **Description**                                                                                                                                                                                     |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DeviceFileEvents**    | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) - Detects the download and installation of AnyDesk, and creation/deletion of suspicious files.       |
| **DeviceProcessEvents** | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) - Detects silent install, execution of AnyDesk processes, and clipboard interactions.             |
| **DeviceNetworkEvents** | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) - Monitors outbound connections made by `AnyDesk.exe`, especially to AnyDesk relay IPs and ports. |

Related queries

// Detect AnyDesk being downloaded
DeviceFileEvents
| where FileName =~ "AnyDesk.exe"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName

// Detect silent installation with startup configuration
DeviceProcessEvents
| where ProcessCommandLine has "--start-with-win"
| where FileName =~ "AnyDesk.exe"
| project Timestamp, DeviceName, ProcessCommandLine, AccountName

// AnyDesk executable launched
DeviceProcessEvents
| where FileName =~ "AnyDesk.exe"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine

// AnyDesk network traffic
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "AnyDesk.exe"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine

// Detect possible file exfiltration attempt
DeviceFileEvents
| where FileName =~ "personal_backup.zip"
| project Timestamp, DeviceName, ActionType, FolderPath

// Detect clipboard activity if monitored by EDR
DeviceEvents
| where ActionType == "ClipboardAccessed"
| where InitiatingProcessFileName =~ "AnyDesk.exe"


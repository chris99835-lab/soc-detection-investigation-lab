# SOC Detection & Investigation Home Lab

## Overview

This project documents a hands-on Security Operations Center (SOC) home lab built to practice endpoint monitoring, log analysis, threat detection, investigation, and alerting.

I configured a Windows 11 virtual machine as a monitored endpoint, deployed Sysmon for enhanced endpoint telemetry, and ingested Sysmon and Windows Security logs into Splunk Enterprise.

Using Splunk Search Processing Language (SPL), I investigated Windows activity, analyzed authentication failures, examined process execution and parent-child relationships, reviewed DNS and file activity, and created automated alerts for suspicious behavior.

## Lab Environment

- Windows 11
- VMware Workstation
- Splunk Enterprise
- Sysmon
- Windows Security Event Logs
- PowerShell
- Splunk Processing Language (SPL)

## Skills Demonstrated

- SIEM log ingestion and analysis
- Windows endpoint monitoring
- Sysmon event analysis
- SPL query development
- Process and parent-child process investigation
- Windows authentication failure analysis
- DNS activity investigation
- File creation monitoring
- Registry activity investigation
- Detection engineering
- Automated alert creation
- SOC investigation workflow

## Data Sources

The lab ingested two primary Windows log sources into Splunk:

- `WinEventLog:Microsoft-Windows-Sysmon/Operational`
- `WinEventLog:Security`

These logs provided visibility into endpoint behavior and Windows authentication/security activity.
## Log Ingestion & Visibility

Splunk Enterprise was configured to ingest telemetry from both Sysmon and the Windows Security event log. This provided centralized visibility into endpoint activity and authentication events from the Windows 11 endpoint.

During validation, Splunk successfully returned:

- 5,146 Sysmon events
- 1,117 Windows Security events
- 6,263 total events within the selected 24-hour search window

This confirmed that both primary data sources were successfully being collected and searchable within the SIEM.

### Evidence

The screenshot below demonstrates successful ingestion of both Sysmon and Windows Security telemetry into Splunk.

![Splunk log ingestion showing Sysmon and Windows Security events](01-splunk-log-ingestion.png)

## Detection 1: Suspicious PowerShell Activity

### Objective

Identify and investigate potentially suspicious PowerShell execution using Sysmon process creation telemetry.

### Investigation

I used Sysmon Event ID 1 data in Splunk to analyze PowerShell process execution. The investigation focused on process details such as the executing user, process image, command line, process ID, and parent process information.

This demonstrated how endpoint process telemetry can be used during SOC triage to identify and investigate potentially suspicious command-line activity.

### Detection Logic

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
``` 
### Detection Evidence

The SPL detection successfully identified PowerShell activity matching the suspicious command-line criteria.

![Suspicious PowerShell detection in Splunk](02-powershell-detection.png)

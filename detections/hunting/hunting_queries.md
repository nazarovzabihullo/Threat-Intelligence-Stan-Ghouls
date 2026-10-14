# Threat Hunting Queries: Stan Ghouls Campaign

Author: **Nazarov Zabihullo** (@Nazarov_Zabihullo)  
Threat Group: **Stan Ghouls (aka Bloody Wolf)**  
Target: **Uzbekistan & Central Asia**  
Malware: **NetSupport RAT / Custom JAR Dropper**

---

## 1. Microsoft Sentinel / Defender for Endpoint (KQL)

### Query 1: Suspicious `client32.exe` Execution
```kql
DeviceProcessEvents
| where FileName =~ "client32.exe"
| where FolderPath has_any ("AppData", "Temp", "Roaming", "Users\\Public")
        or InitiatingProcessFileName in~ ("cmd.exe", "powershell.exe", "javaw.exe", "java.exe")
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| sort by Timestamp desc
```

### Query 2: Persistence via Startup Folder or Registry Run Key
```kql
DeviceRegistryEvents
| where ActionType =~ "RegistryValueSet"
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueData has_any ("run.bat", "SoliqUZ_Run.bat", "bat_install.bat")
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
```

### Query 3: Network Connections to Known C2 Infrastructure
```kql
DeviceNetworkEvents
| where RemoteUrl has_any (
    "mysoliq-uz.com", "soliq-uz.com", "my-xb.com", "xarid-uz.com", "ach-uz.com",
    "minjust-kg.com", "esf-kg.com", "taxnotice-kg.com", "golden-scalen.com", "xoomep1.com", "xoomep2.com"
  )
  or RemoteIP in ("31.44.4.40", "188.227.58.243", "188.227.106.124", "45.133.16.135", "193.42.32.138", "87.251.67.51")
  or RemotePort == 1935
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
```

---

## 2. Splunk Enterprise Security (SPL)

### Query 1: Detection of NetSupport Client Execution from AppData
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\client32.exe" (ParentImage="*\\cmd.exe" OR ParentImage="*\\java*.exe" OR Image="*\\AppData\\*")
| table _time, host, user, Image, CommandLine, ParentImage, ParentCommandLine
```

### Query 2: Hunting Scheduled Task with ONLOGON
```spl
index=endpoint sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*\\schtasks.exe" CommandLine="*malicious*" CommandLine="*ONLOGON*"
| table _time, host, user, CommandLine, ParentCommandLine
```

### Query 3: DNS Query Traffic to Spoofed Uzbek / Kyrgyz Domains
```spl
index=network sourcetype="stream:DNS" OR sourcetype="suricata:dns"
query IN ("*mysoliq-uz.com*", "*soliq-uz.com*", "*my-xb.com*", "*xarid-uz.com*", "*ach-uz.com*", "*minjust-kg.com*", "*golden-scalen.com*")
| stats count earliest(_time) as first_seen latest(_time) as last_seen by src_ip, query
```

---

## 3. Elasticsearch / Kibana (EQL)

```eql
sequence by host.id with maxspan=5m
  [process where event.category == "process" and process.name in ("java.exe", "javaw.exe")]
  [file where event.category == "file" and file.name in ("run.bat", "SoliqUZ_Run.bat", "client32.exe")]
  [process where event.category == "process" and process.name == "client32.exe"]
```

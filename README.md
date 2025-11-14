# SOC-Project-01 — Detecting PowerShell Base64 Obfuscation (MITRE ATT&CK T1059.001)

This SOC project demonstrates the detection and analysis of obfuscated PowerShell execution using Sysmon.  
The activity was intentionally generated on a local workstation to simulate common attacker behavior.

---

## 🔎 Summary

Technique: PowerShell Execution with Base64 Obfuscation  
MITRE ATT&CK: T1059.001  
Tools: Sysmon 15.15, SwiftOnSecurity Sysmon Config  
Log Source: Microsoft-Windows-Sysmon/Operational  
Event ID: 1 (Process Create)

This simulation represents how attackers use encoded PowerShell commands to evade detection.

---

## 🔥 1. Triggered Command (Simulated Attack)

Command executed:  
`powershell.exe -enc SQBFAFgAIAAoACcAVABFU1QtU09DICcAKQA=`

Decoded payload:  
`IEX ('TEST-SOC')`

The payload is harmless, but the execution technique mimics real-world malware behavior.

---

## 🔍 2. Sysmon Event — Key Details

Event ID 1 — Process Create (Sysmon)

Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`  
CommandLine: `"powershell.exe" -enc SQBFAFgAIAAoACcAVABFU1QtU09DICcAKQA=`  
IntegrityLevel: `High`  
User: `APACS-PC\Apacs3000`  
ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`  
RuleName: `technique_id=T1059.001,technique_name=PowerShell`

Indicators of interest:
- Use of `-enc` (Base64 obfuscation)
- PowerShell spawned by PowerShell (parent-child chain)
- High-privilege execution
- Automatic MITRE tagging via Sysmon rules

---

## 🧠 3. SOC Triage (L1 Analysis)

Is this suspicious?  
Yes. Encoded PowerShell is strongly associated with:

- Payload delivery  
- Defense evasion  
- Credential theft  
- Obfuscated malware execution  
- LOLBAS abuse  

Why this matters:
- Encoded commands hide the real intent
- PowerShell → PowerShell parent-child chain is uncommon for normal user activity
- MITRE mapping (T1059.001) is a red flag

Final verdict:  
Benign — training simulation, but behavior fully matches attacker tradecraft.

---

## 🛠 4. Lab Environment

OS: Windows 10  
Sysmon: v15.15  
Config: SwiftOnSecurity `sysmonconfig.xml`  
Log viewer: Windows Event Viewer (Microsoft-Windows-Sysmon/Operational)

---

## 📸 5. Screenshots (Recommended Structure)

Put screenshots into:

- `screenshots/sysmon-event.png`  
- `screenshots/base64-command.png`  
- `screenshots/xml-log.png`

---

## 🎯 6. What This Project Demonstrates

- Setting up Sysmon for security monitoring  
- Detecting encoded PowerShell commands  
- Mapping events to MITRE ATT&CK  
- L1 SOC alert triage workflow  
- Proper incident documentation  
- Building a real SOC portfolio project for recruiters  

---

## 🧩 MITRE ATT&CK Mapping

Technique ID: `T1059.001`  
Name: `PowerShell`  
Description: Adversaries execute malicious or obfuscated PowerShell commands.

---

## 👤 Author

Maksim Talalayko  
SOC & Operational Security  

GitHub: https://github.com/asp2peaK  
TryHackMe: https://tryhackme.com/p/maksim.talalayko  

---

## 🔖 Tags

SOC • Blue Team • Sysmon • PowerShell • MITRE ATT&CK • T1059 • Incident Response • DFIR • Windows Security • SIEM

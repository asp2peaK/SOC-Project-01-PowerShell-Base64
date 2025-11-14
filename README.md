# SOC-Project-01-PowerShell-Base64

# SOC Project 01 — Detecting PowerShell Base64 Obfuscation (MITRE ATT&CK T1059.001)

This SOC project demonstrates the detection and analysis of obfuscated PowerShell execution using Sysmon.  
The activity was intentionally generated on a lab workstation to simulate common attacker behavior.

---

## 📌 Summary

**Technique:** PowerShell Execution with Base64 Obfuscation  
**MITRE ATT&CK:** T1059.001  
**Tools:** Sysmon 15.15, SwiftOnSecurity Sysmon Config  
**Log Source:** Microsoft-Windows-Sysmon/Operational  
**Event ID:** 1 (Process Create)

This simulation represents how attackers use encoded PowerShell payloads to evade detection.

---

## 🔥 1. Triggered Command (Simulated Attack)

Command executed:

```powershell
powershell.exe -enc SQBFAFgAIAAoACcAVABFU1QtU09DICcAKQA=
Decoded payload:

powershell
Копировать код
IEX ('TEST-SOC')
The payload is benign, but the behavior fully mimics malicious obfuscated execution.

🔍 2. Sysmon Event — Key Details
Event ID 1 — Process Create

xml
Копировать код
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "powershell.exe" -enc SQBFAFgAIAAoACcAVABFU1QtU09DICcAKQA=
IntegrityLevel: High
User: APACS-PC\Apacs3000
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
RuleName: technique_id=T1059.001,technique_name=PowerShell
Indicators:

Use of “-enc” (Base64 obfuscation)

PowerShell spawned by PowerShell

High integrity execution

MITRE technique tagging from Sysmon

🧠 3. SOC Triage (L1 Analysis)
Is it suspicious? — Yes.
Encoded PowerShell is widely used for payload delivery, persistence, and credential theft.

🔎 Indicators of Interest
Encoded command execution

High privileges

Parent–child PowerShell chain

Behavior mapped to MITRE automatically

✔ Final Verdict
Benign (lab simulation)
But behavior fully matches real attacker tradecraft.

🛠 4. Lab Environment
OS: Windows 10

Sysmon: v15.15

Config: SwiftOnSecurity sysmonconfig.xml

Log Viewer: Windows Event Viewer (Sysmon Operational Log)

🖼 5. Screenshots (Add to Repository)
Suggested files:

bash
Копировать код
/screenshots/sysmon-event.png
/screenshots/base64-command.png
/screenshots/xml-log.png
🎯 6. What This Project Demonstrates
Setting up Sysmon for monitoring

Detecting encoded PowerShell commands

Mapping to MITRE ATT&CK

Log triage fundamentals

Creating structured SOC documentation

Using Event Viewer for DFIR and detection engineering

📚 MITRE ATT&CK Mapping
Technique	Name	Description
T1059.001	PowerShell	Adversaries execute malicious or obfuscated commands via PowerShell

👤 Author
Maksim Talalayko
SOC & Operational Security
GitHub: https://github.com/asp2peaK
TryHackMe: https://tryhackme.com/p/maksim.talalayko

🔖 Tags
SOC Blue Team Sysmon PowerShell MITRE ATT&CK T1059 Incident Response DFIR Windows Security SIEM

# Executive Summary: Stan Ghouls (Bloody Wolf) Cyber Espionage & Financial Fraud Campaign

**Classification:** TLP:CLEAR  
**Prepared By:** Nazarov Zabihullo (Cyber Threat Intelligence Analyst)  
**Contact:** [Telegram: @Nazarov_Zabihullo](https://t.me/Nazarov_Zabihullo) | +998 33 737 37 03  
**Target Region:** Uzbekistan (Primary), Kyrgyzstan, Kazakhstan, Russia, Turkey, Serbia, Belarus  
**Victim Scale:** 60+ Confirmed Institutional & Corporate Compromises (50+ in Uzbekistan)  

---

## Strategic Overview

During Q3-Q4, a sophisticated cybercrime threat syndicate tracked as **Stan Ghouls** (previously known in threat intelligence circles as **Bloody Wolf**) launched a wide-scale spearphishing offensive against state institutions, accounting departments, and private enterprises across Central Asia, with the heaviest concentration in **Uzbekistan**.

The adversary’s primary objective is **financial theft and banking fraud (MITRE T1657)**. By masquerading as the Uzbek Judicial Department (spoofing `E-SUD` court summons execution documents) and the State Tax Committee (`soliq-uz`, `mysoliq-uz`), the threat actor systematically deployed weaponized remote management software (**NetSupport RAT**) alongside a secondary **BurnsRAT** backdoor.

```
       [Spearphishing Email]
                 │
                 ▼
  [Decoy PDF: E-SUD Enforcement Lure]
                 │
                 ▼
     [Geo-Checked Malicious Link]
                 │ (Uzbek IP Verified)
                 ▼
   [Obfuscated JAR Dropper (3x Loop)]
                 │
                 ▼
     [NetSupport RAT (client32.exe)]
                 │
 ┌───────────────┴───────────────┐
 ▼                               ▼
[Triple Persistence Layer]   [C2 Traffic (Port 1935 / HTTP)]
- HKCU Run Key               - Keylogging & Screen Sniffing
- Startup SoliqUZ_Run.bat    - Banking Session Hijacking
- Scheduled Task (ONLOGON)   - Financial Exfiltration
```

---

## Key Risk Factors & Novel Techniques

1. **Environmental Geofencing (T1480.001):** The threat actor implemented server-side IP filtering. Sandboxes or analysts outside Uzbekistan receive innocuous 404/dummy responses, while Uzbek IP addresses receive the malicious payload.
2. **Prerequisite Java Runtime Exploitation:** To overcome Windows systems lacking Java environments by default, the adversary crafted persuasive lured steps forcing manual or assisted installation of Java to execute their single-class JAR dropper (`MD5: 95db93454ec1d581311c832122d21b20`).
3. **Sandbox Evasion via Execution Loop Quotas:** The JAR loader terminates execution after exactly 3 failed attempts, defeating automated dynamic analysis sandboxes designed to re-run processes multiple times.
4. **Triple-Vector Persistence:** Ensures complete reboot survivability using:
   - Registry Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` -> `run.bat`
   - Startup Directory: `%AppData%\...\Startup\SoliqUZ_Run.bat`
   - System Scheduler: `schtasks /TN malicious /TR run.bat /SC ONLOGON`

---

## Business & Operational Impact

- **Direct Financial Risk:** Unauthorized access to corporate bank portals (such as interbank clearing lures `ach-uz.com`, `my-xb.com`).
- **Data Espionage:** Full-screen surveillance (`T1113`) and real-time keylogging (`T1056.001`) granting access to confidential business contracts and government correspondence.
- **Brand Reputation:** Spoofing national institutions undermines public trust in e-government platforms (`E-SUD`, `soliq.uz`, `xarid.uz`).

---

## Strategic Recommendations for Leadership

| Domain | Immediate Action |
|---|---|
| **Email Gateway** | Block incoming emails containing attachments or links to `.jar`, `.bat`, or untrusted cloud file stores. |
| **Endpoint Security** | Deploy behavioral Sigma/EDR rules preventing `cmd.exe` or `java.exe` from spawning binaries in user `%AppData%`. |
| **DNS & Perimeter** | Ingest defanged IoC list (`iocs/iocs.csv`) directly into perimeter firewalls and secure web gateways (SWG). |
| **User Awareness** | Train accounting and procurement staff to verify court notifications exclusively through official `esud.sud.uz` and `soliq.uz` domains. |

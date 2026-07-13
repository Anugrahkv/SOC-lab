# SOC Lab — Attack Simulations (Attacks #1–4)

> **Lab built by:** Anugrah K  
> **Goal:** Simulate real-world attack techniques and verify detection across network, host, and application layers using Wazuh SIEM + Snort IDS.  
> **Attacker VM:** Kali Linux (192.168.56.10)  
> **Target VM:** Ubuntu Server 24.04 (192.168.56.20)  
> **SIEM:** Wazuh 4.14 all-in-one (192.168.56.40)  
> **IDS:** Snort (host-based, running on Target-Victim)

---

## Lab Topology

```
Kali Attacker (.10) ──────► Target-Victim (.20)
                                │
                         Snort IDS (host-based)
                         Wazuh Agent
                                │
                                ▼
                       Wazuh Server (.40)
                    SIEM Dashboard + Telegram Alerts
```

---

## Detection Pipeline

```
Attack launched from Kali
       │
       ▼
Snort detects at network level  ──► /var/log/snort/snort.alert.fast
       │
Wazuh agent reads Snort log  ──► forwards to Wazuh Manager
       │
Wazuh Manager correlates  ──► Alert in dashboard + Telegram push
```


## Attack #1 — ICMP Sweep / Ping Recon

| Field | Detail |
|---|---|
| **MITRE ATT&CK** | T1018 – Remote System Discovery |
| **Tool** | ping (built-in) |
| **Command** | `ping -c 5 192.168.56.20` |
| **Detection layer** | Network (Snort custom rule) |
| **Snort rule** | `alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected - Possible Recon"; sid:1000001; rev:1;)` |
| **Wazuh rule fired** | 20101 – IDS Event (Level 6) |
| **Correlation rule** | 20152 – Multiple IDS alerts for same ID (Level 10) |
| **Source IP detected** | 192.168.56.10 ✅ |

### What happened
An attacker performing initial reconnaissance pings a target to confirm it's alive before launching further attacks. This is one of the first steps in the MITRE ATT&CK kill chain — discovery.

### Detection proof
> <img width="1919" height="1128" alt="attack01_icmp_target_terminal" src="https://github.com/user-attachments/assets/1a15df34-c2af-4631-90d6-fb2413e2b715" />

> <img width="1920" height="1100" alt="attack01_icmp_wazuh_terminal" src="https://github.com/user-attachments/assets/4013f51d-e199-47e0-b65e-df5c9397d65d" />

> <img width="1920" height="428" alt="attack01_icmp_dashboard_overview" src="https://github.com/user-attachments/assets/e2351c22-8904-42bd-8cdf-188e0635962a" />

> <img width="1920" height="1113" alt="attack01_icmp_dashboard_expanded" src="https://github.com/user-attachments/assets/5625131b-05b2-4852-a668-1627310be221" />

> <img width="1919" height="363" alt="attack01_icmp_dashboard_expanded 2" src="https://github.com/user-attachments/assets/26305141-141c-462f-ba75-7acdc17a4c6b" />

> <img width="1314" height="1111" alt="telegram alert" src="https://github.com/user-attachments/assets/a729c979-7718-4965-aee5-eab263c7544c" />


### Mitigation
- Block unnecessary ICMP echo requests at the network perimeter (firewall `iptables -A INPUT -p icmp --icmp-type echo-request -j DROP`)
- Enable Snort detection rules for ICMP-based recon
- Monitor for rapid/repeated ICMP to multiple hosts (indicates network sweep, not just single-host testing)

---

## Attack #2 — Nmap SYN Port Scan (Full Range)

| Field | Detail |
|---|---|
| **MITRE ATT&CK** | T1046 – Network Service Discovery |
| **Tool** | Nmap |
| **Command** | `nmap -sS -p- 192.168.56.20` |
| **Detection layer** | Network (Snort threshold rule) |
| **Snort rule** | `alert tcp any any -> $HOME_NET any (msg:"Possible Nmap TCP Scan Detected"; flags:S; threshold:type threshold, track by_src, count 5, seconds 10; sid:1000002; rev:1;)` |
| **Wazuh rule fired** | 20101 – IDS Event (Level 6), 20152 – Multiple IDS alerts (Level 10) |
| **Ports scanned** | 1–65535 |
| **Source IP detected** | 192.168.56.10 ✅ |

### What happened
A full SYN scan maps every open port on the target. Attackers use this to identify services to exploit. The threshold-based rule fires when 5+ SYN packets arrive from the same source within 10 seconds — a reliable behavioral pattern distinguishing scans from normal traffic.

### Detection proof
> <img width="1920" height="1113" alt="attack02_nmap_target_terminal" src="https://github.com/user-attachments/assets/32d18431-7def-46f7-b9c2-bbd878805b7a" />

> <img width="1920" height="1137" alt="attack02_nmap_wazuh_terminal" src="https://github.com/user-attachments/assets/5a168320-fd93-4b5d-a7b4-7b79ac4de1f9" />

> <img width="1920" height="1133" alt="attack02_nmap_dashboard_overview" src="https://github.com/user-attachments/assets/30465a7e-7cd9-4b98-b64c-110b3032162c" />

> <img width="1920" height="1138" alt="attack02_nmap_dashboard_overview 2" src="https://github.com/user-attachments/assets/e59177ff-8c43-4da1-b8c4-6b8a646250c4" />

> <img width="1912" height="1111" alt="attack02_nmap_dashboard_expanded" src="https://github.com/user-attachments/assets/c2d8e631-0fd6-4ac8-a5b3-a93968caadcb" />

> <img width="1917" height="397" alt="attack02_nmap_dashboard_expanded 2" src="https://github.com/user-attachments/assets/2d928ae3-bd2b-486c-b805-199a48433ad7" />

> <img width="1305" height="420" alt="telegram alert" src="https://github.com/user-attachments/assets/d9f75b18-de8f-45d6-beba-68b78d7f3436" />



### Mitigation
- Implement port knocking or firewall rate limiting on SSH/web ports
- Use iptables recent module to detect and block rapid connection attempts: `iptables -A INPUT -p tcp --syn -m recent --name portscan --set -j DROP`
- Alert on high-volume SYN traffic from single source as a scan indicator

---

## Attack #3 — SSH Brute Force (Hydra)

| Field | Detail |
|---|---|
| **MITRE ATT&CK** | T1110.001 – Brute Force: Password Guessing |
| **Tool** | Hydra |
| **Command** | `hydra -l testuser -P passwords.txt ssh://192.168.56.20 -t 4` |
| **Detection layer** | Host (Wazuh native auth.log analysis) |
| **Target account** | testuser (intentionally weak password) |
| **Wazuh rules fired** | Multiple auth failures → Successful login after failures (Level 10+) |
| **Telegram alert** | ✅ Fired in real time |
| **Source IP detected** | 192.168.56.10 ✅ |

### What happened
Hydra systematically tried a wordlist of passwords against SSH. After 6 failed attempts, it found the correct credential (`password123`) and successfully authenticated. Wazuh detected both the pattern of failures **and** the critical signal — a successful login after repeated failures — which is the clearest indicator of a compromised credential.

### Key lesson learned
`/var/log/auth.log` was not in the default Wazuh agent localfile configuration. It had to be added manually. **A SIEM only detects what it's actually reading** — verifying log source coverage is a critical operational step.

### Detection proof
> <img width="1441" height="181" alt="attack03_ssh_bruteforce_target_terminal" src="https://github.com/user-attachments/assets/e7e9c28e-dd1f-46b4-b472-405a6721c39d" />

> <img width="1920" height="507" alt="attack03_ssh_bruteforce_wazuh_terminal" src="https://github.com/user-attachments/assets/52c248bd-e743-4314-b3d2-6e7f422ba442" />

> <img width="1920" height="765" alt="attack03_ssh_bruteforce_dashboard_overview" src="https://github.com/user-attachments/assets/5e800eb3-2fae-4c6d-8b0f-eb80843592c2" />

> <img width="1920" height="1116" alt="attack03_ssh_bruteforce_dashboard_expanded" src="https://github.com/user-attachments/assets/a2a2bbe8-5e20-4dfa-873a-a2383bc42c49" />

> <img width="1920" height="595" alt="attack03_ssh_bruteforce_dashboard_expanded 2" src="https://github.com/user-attachments/assets/be7cd104-362d-4cbf-9d5e-37ae6dc7ee42" />

> <img width="1304" height="751" alt="telegram alert" src="https://github.com/user-attachments/assets/dc762468-09ef-4bd1-a5de-c48bc417be7d" />


### Mitigation
- Enforce SSH key-based authentication only: `PasswordAuthentication no` in `/etc/ssh/sshd_config`
- Install fail2ban to auto-block IPs after repeated failures: `sudo apt install fail2ban`
- Implement account lockout policy after N failed attempts
- Restrict SSH access to known management IPs via firewall rules

---

## Attack #4 — Web Directory Brute Force (Gobuster)

| Field | Detail |
|---|---|
| **MITRE ATT&CK** | T1595.003 – Active Scanning: Wordlist Scanning |
| **Tool** | Gobuster |
| **Command** | `gobuster dir -u http://192.168.56.20 -w /usr/share/wordlists/dirb/common.txt -t 20` |
| **Detection layer** | Application (Wazuh Apache access.log analysis) |
| **Discovered paths** | /admin, /backup, /config |
| **Wazuh rules fired** | Web scanning / multiple 404 pattern rules |
| **Source IP detected** | 192.168.56.10 ✅ |

### What happened
Gobuster enumerated directories against an Apache web server using a common wordlist. The rapid flood of HTTP requests — mostly 404s, with 200 responses for sensitive paths — created a detectable pattern in the access log. Wazuh's web application rules flagged the scanning behavior.

### Detection proof
> <img width="1920" height="1134" alt="attack04_gobuster_target_terminal" src="https://github.com/user-attachments/assets/d6a0a12b-6f91-46ea-8325-4667e848cc9d" />

> <img width="1129" height="363" alt="attack04_gobuster_wazuh_terminal" src="https://github.com/user-attachments/assets/cffd74e5-e8f9-4536-b8f3-21261afb92ee" />

> <img width="1920" height="1127" alt="attack04_gobuster_dashboard_overview" src="https://github.com/user-attachments/assets/17c7fac7-8311-4167-a73d-459df434300b" />

> <img width="1920" height="1118" alt="attack04_gobuster_dashboard_expanded" src="https://github.com/user-attachments/assets/3503b68b-166f-4a6b-adb2-1e8d27b57b43" />

> <img width="1917" height="591" alt="attack04_gobuster_dashboard_expanded 2" src="https://github.com/user-attachments/assets/2fa93617-84d9-456a-96c2-7a8e61fd249b" />

> <img width="1305" height="1107" alt="telegram alert" src="https://github.com/user-attachments/assets/23166fdc-3e2a-4a8b-ae42-53530fcc5c2e" />

### Mitigation
- Remove or password-protect sensitive directories (`/admin`, `/backup`)
- Implement rate limiting via Apache `mod_evasive`
- Return 403 instead of 404 for sensitive paths to reduce information leakage
- Use a WAF (Web Application Firewall) to detect and block directory enumeration patterns

---

## Summary Table

| # | Attack | MITRE | Tool | Detected | Severity |
|---|---|---|---|---|---|
| 1 | ICMP Recon | T1018 | ping | ✅ Snort sid:1000001 | Level 6 → 10 |
| 2 | Nmap Port Scan | T1046 | nmap | ✅ Snort sid:1000002 | Level 6 → 10 |
| 3 | SSH Brute Force | T1110.001 | hydra | ✅ Wazuh auth.log rules | Level 10+ |
| 4 | Web Dir Scan | T1595.003 | gobuster | ✅ Wazuh Apache rules | Level 7+ |

---

## Lab Lessons Learned

1. **Default configs are never complete** — `auth.log` and `access.log` were both missing from Wazuh's default agent monitoring and had to be added manually. Always audit what your SIEM is actually reading.
2. **A single commented-out variable kills everything silently** — `#var RULE_PATH` in `snort.conf` caused all custom rules to fail to load with no obvious error. Methodical validation (`snort -T`) is essential after every config change.
3. **Threshold-based rules outperform single-event rules for scan detection** — a rule triggering on 5 SYNs in 10 seconds is far more signal-rich than one firing on every individual packet.
4. **SIEM correlation adds real value** — Wazuh's rule 20152 (multiple alerts same ID) escalated low-severity IDS events into high-severity alerts automatically, demonstrating why SIEM correlation logic matters beyond raw log collection.

---

*More attacks coming in the next update — privilege escalation, reverse shells, persistence mechanisms, and data exfiltration.*

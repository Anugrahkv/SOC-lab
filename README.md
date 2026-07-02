# Home SOC Lab — SIEM, IDS & Attack Simulation Environment

A fully self-built Security Operations Center lab running on a single 16 GB laptop, built to practice real detection engineering, log analysis, and incident triage end-to-end — from infrastructure to attack simulation to analyst-style reporting.

## Why I built this

I wanted hands-on experience with the actual tools and workflows a SOC analyst uses day to day — not just reading about SIEM concepts, but standing up a real one, breaking it, fixing it, attacking it, and learning to read what it tells me. This repo documents that build, the mistakes made along the way, and the attack simulations run against it.

## Architecture

<img width="2720" height="2800" alt="soc_lab_topology" src="https://github.com/user-attachments/assets/7a4b0949-0787-4b3f-96a7-d5c93b0efe07" />


| VM | OS | Role | IP | RAM |
|---|---|---|---|---|
| Wazuh Server | Ubuntu Server 24.04 | SIEM/XDR (indexer, manager, dashboard) | 192.168.56.40 | 4 GB |
| Kali Linux | Kali 2026.1 | Attacker / red team | 192.168.56.10 | 2 GB |
| Target-Victim | Ubuntu Server 24.04 | Victim endpoint + host-based Snort IDS | 192.168.56.20 | 1 GB |
| Snort-IDS | Ubuntu Server 24.04 | Dedicated IDS VM (built, currently idle — see note below) | 192.168.56.30 | 1 GB |

**Hypervisor:** Oracle VirtualBox 7.2.10, host-only network (192.168.56.0/24, static IPs via netplan) + NAT Network (10.0.2.0/24) for internet access during installs.

### A deliberate architecture decision worth explaining

VirtualBox host-only networks behave as a simple switch — they don't forward unicast traffic between two VMs to a third VM's interface, even with promiscuous mode enabled. This means a dedicated "network tap" IDS VM, as commonly diagrammed in tutorials, doesn't actually see inter-VM attack traffic in this environment without significant additional complexity (internal network bridging tricks).

Rather than build something that looked architecturally correct but didn't actually work, I made the pragmatic call: **Snort runs directly on Target-Victim**, watching its own interface. It sees 100% of traffic addressed to/from the endpoint it's protecting — which is also a legitimate, common real-world IDS deployment pattern (host-based NIDS). The dedicated Snort-IDS VM remains in the topology, built and networked, to document the alternative architecture and its constraints.

## Stack

- **SIEM/XDR:** Wazuh 4.14 (indexer + manager + dashboard, all-in-one)
- **IDS:** Snort (host-based on Target-Victim)
- **Alerting:** Telegram (custom Python integration, tuned to level 10+ to avoid alert fatigue)
- **Attack platform:** Kali Linux 2026.1
- **Simulate target:** Apache2 with intentionally discoverable directories, weak test account


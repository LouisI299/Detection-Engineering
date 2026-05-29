# Advanced Detection Engineering Lab: Multi-Platform SIEM Pipeline

## 📌 Project Overview

This repository documents a comprehensive **Detection Engineering** project developed during my internship within the lab infrastructure. The core objective of this project is to build a high-fidelity, low-noise detection stack by constructing a functional SIEM ingestion pipeline, simulating advanced adversary tactics, techniques, and procedures (TTPs), and authoring custom detection rules using the **Sigma and Sigma Correlation (Sigma-C)** standards.

Rather than relying on default out-of-the-box alerts, this project focuses on engineering multi-log source temporal correlations (Endpoint + Network) to eliminate alert fatigue and catch sophisticated, low-variance behavior.

---

## 🏗️ Lab Architecture & Network Topology

The lab environment replicates a hardened enterprise infrastructure divided into three isolated VLANs, routed and inspected by a central **FortiGate Next-Generation Firewall (NGFW)**. All telemetry, alerts, and raw logs generated across this architecture are ingested into **Sekoia.io**, the central SIEM for this project. Sekoia.io serves as the primary detection engine where all custom Sigma and Sigma-C rules are compiled, deployed, and rigorously tested against live adversary emulations.

### Network Segmentation

- **VLAN 60: Servers Zone**
  - **Active Directory Domain Controller (Windows Server 2022):** Generates core identity logs. Equipped with **Sysmon** and utilizing **NXLog** to stream Windows Event Logs directly to Sekoia.io.
  - **SIEM Forwarder Host (Linux Ubuntu VM):** Runs the **Sekoia.io Forwarder** natively inside a Docker container, acting as the centralized syslog collector for the Fortigate NGFW.
- **VLAN 70: Clients Zone**
  - **Windows 11 Pro Endpoint:** Monitored via **CrowdStrike Falcon**, which streams alert and detection logs directly to Sekoia.io via API integration.
  - **Windows Server 2019 Endpoint:** Monitored via **SentinelOne (S1)**, configured to stream alert and detection logs directly to Sekoia.io via API integration.
- **VLAN 80: Attacker Zone**
  - **Kali Linux:** Dedicated simulation platform used to execute manual exploitation tools (e.g., Impacket, Hydra, Mimikatz).
  - **Atomic Red Team (ART):** Deployed directly on targeted endpoints to execute automated, highly controlled adversary emulation plays.

---

## 📂 Repository Structure

The detection codebase is organized by data source and integration level, containing over 30 engineered Sigma rules mapped to the MITRE ATT&CK framework.

```text
.
├── Rules/
│   ├── Active_Directory/                 # Identity, Process, and Windows Event detections
│   │   ├── cor_win_ad_brute_force_success_t1110_001.yaml
│   │   ├── cor_win_ad_brute_force_t1110_001.yaml
│   │   ├── win_ad_abuse_of_domain_accounts_t1078_002.yaml
│   │   ├── win_ad_create_or_modify_system_process_t1543_003.yaml
│   │   ├── win_ad_credential_dumping_dcsync_t1003_006.yaml
│   │   ├── win_ad_filecreation_event_triggered_execution_t1546_003.yaml
│   │   ├── win_ad_pass_the_hash_t1550_002.yaml
│   │   ├── win_ad_process_1m_account_discovery_domain_account_t1087.yaml
│   │   ├── win_ad_process_account_discovery_domain_account_t1087.yaml
│   │   ├── win_ad_process_event_triggered_execution_t1546_003.yaml
│   │   ├── win_ad_process_inhibit_system_recovery_T1490.yaml
│   │   ├── win_ad_process_windows_management_instrumentation_t1047.yaml
│   │   ├── win_ad_script_1m_account_discovery_domain_account_t1081.yaml
│   │   ├── win_ad_script_account_discovery_domain_account_t1081.yaml
│   │   ├── win_ad_script_inhibit_system_recovery_T1490.yaml
│   │   ├── win_ad_script_windows_management_instrumentation_t1047.yaml
│   │   ├── win_ad_wmi_event_triggered_execution_t1546_003.yaml
│   │   └── win_ad_wmi_inhibit_system_recovery_T1490.yaml
│   ├── EDR_Rules/                        # Native EDR telemetry indicators
│   │   ├── crowdstrike_brute_force_attempt.yaml
│   │   ├── crowdstrike_brute_force_succesful.yaml
│   │   ├── crowdstrike_c2_over_web_protocol.yaml
│   │   ├── crowdstrike_exfiltration_over_non_c2_protocol.yaml
│   │   ├── s1_brute_force_attempt.yaml
│   │   ├── s1_brute_force_succesful.yaml
│   │   ├── s1_c2_over_web_protocol.yaml
│   │   └── s1_exfiltration_over_non_c2_protocol.yaml
│   ├── Fortigate/                        # Network layer & firewall session logs
│   │   └── cor_fortigate_active_scanning.yaml
│   └── Multi_Platform/                   # Complex multi-source correlation rules
│       ├── cor_C2_over_web_protocol_t1071.yaml
│       └── cor_exfiltration_over_non_c2_protocol_t1048.yaml
├── docs/                                 # Comprehensive Technical Documentation
│   ├── Active_Directory/                 # Attack walk-throughs & rule mechanics for AD
│   └── Multi_Platform/                   # Logic write-ups for multi-source alerts
├── images/                               # Evidence vault (Alert screenshots, testing)
├── .gitignore
├── Backlog.md                            # Living tracking board with 100+ MITRE-mapped rule candidates
└── README.md                             # Project blueprint and architecture brief
```

## 🚀 Engineered Detections & MITRE ATT&CK Mapping

This framework prioritizes **high-fidelity alerts over raw detection noise**. The engine suppresses individual base events, storing them silently in memory, and **only triggers a visible critical alert** when a Master Correlation condition is completely fulfilled.

### 1. Identity, Credential Access & Directory Services (Active Directory)

- **T1110.001 - Brute Force:** Correlates multiple failed authentications with subsequent successful logins to identify automated password guessing.
- **T1003.006 - OS Credential Dumping (DCSync):** Leverages Event ID `4662` (Directory Service Access) to detect unauthorized replication requests toward the Domain Controller originating from non-machine accounts.
- **T1550.002 - Pass the Hash:** Detects lateral movement techniques leveraging stolen NTLM hashes.
- **T1078.002 - Valid Accounts (Domain Accounts):** Monitors for the anomalous abuse of compromised domain accounts to escalate privileges or access restricted resources.
- **T1081 - Credentials in Files:** Identifies scripts or processes aggressively searching the file system for hardcoded passwords or sensitive configuration files.

### 2. Endpoint Execution, Persistence & Impact

- **T1490 - Inhibit System Recovery:** Detects ransomware-adjacent behavior, such as scripts or processes attempting to delete shadow copies, disable recovery environments, or modify boot configurations.
- **T1546.003 - Event Triggered Execution (WMI):** Monitors for malicious WMI event subscriptions and file creation triggers used for stealthy persistence.
- **T1543.003 - Create or Modify System Process (Windows Service):** Monitors registry modifications (Event ID `13` / `4657`) targeting `\CurrentControlSet\Services\` to intercept unauthorized service creations for persistence.
- **T1047 - Windows Management Instrumentation:** Identifies the malicious use of WMI via process and script telemetry (e.g., `WmiPrvSE.exe` spawning suspicious child processes) for execution and lateral movement.
- **T1087 - Account Discovery:** Identifies aggressive, high-volume domain account querying (e.g., BloodHound/SharpHound) through process and script execution analysis.

### 3. Network & Multi-Platform Correlations

- **T1071.001 - Automated C2 over Web Protocol:** \* _Mechanism:_ Captures low/zero-variance automated network beaconing. It correlates raw EDR endpoint telemetry (`powershell.exe` making outbound requests) with network firewall logs (`destination.port: 80/443` and `action.type: forward`).
  - _Logic:_ An `event_count` rule counts firewall sessions. If a host initiates $\ge 10$ sessions with identical byte counts within 5 minutes to the same destination, it triggers. A final `temporal` correlation ties this to the EDR process activity inside a timeframe window, generating a single **Critical** alert.
- **T1048.003 - Exfiltration Over Non-C2 Protocol:**
  - _Mechanism:_ Pairs endpoint telemetry with mass-data movement. It matches an EDR-identified suspicious connection with a FortiGate network event indicating a singular outbound session moving $\ge 20\text{MB}$ of data, grouped tightly by `source.ip` and `destination.ip` within a 5-minute matrix.
- **T1595 - Active Scanning:**
  - _Mechanism:_ Analyzes FortiGate network layer logs to identify internal or external assets conducting aggressive port or vulnerability scans across the infrastructure, establishing early-warning recon alerts.

---

## 🛠️ Simulation & Validation Methodology

Every rule in this repository has been rigorously verified using a "build-test-verify" lifecycle:

1.  **Emulation:** Attacks are launched from the Kali Linux node or via Atomic Red Team scripts (e.g., executing looped `Invoke-WebRequest -UseBasicParsing` loops to simulate deterministic C2 traffic, or running Impacket for DCSync).
2.  **Telemetry Audit:** Verification that both the endpoint (SentinelOne/CrowdStrike/Sysmon) and network (FortiGate) successfully generated, normalized, and forwarded the raw data points into Sekoia.
3.  **Correlation Tuning:** Ensuring that field aliases (e.g., mapping `sentinelone.data.srcip` to `source.ip`) successfully align across different log structures within the SIEM memory pipeline to avoid false negatives.

---

## 🚧 Project Status: Active Development

This repository represents a living, ongoing detection engineering project. While the core SIEM architecture and the highlighted detection rules are fully functional and validated, the repository is continuously evolving:

- **Rule Tuning:** Several custom rules in the `/Rules` directory are currently in the testing and tuning phase to optimize threshold limits and reduce false-positive rates.
- **Documentation:** The `/docs` folder is actively being expanded. Not all rules have their corresponding attack simulation walk-throughs and SIEM evidence cards finalized yet.
- **Backlog:** Refer to the `Backlog.md` file for visibility into the upcoming detection engineering pipeline and future MITRE ATT&CK coverage goals.

---

## ⚠️ Professional Disclaimer

_This repository exists strictly for educational, defensive research, and authorized detection engineering lab purposes. All attack simulations, proof-of-concept components, and execution steps showcased within the documentation were conducted inside an entirely isolated, legally approved, and non-production training environment. Do not attempt to run these simulation scripts or utilize these configurations against environments without explicit, written authorization._

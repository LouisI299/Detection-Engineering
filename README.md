# Detection Engineering Internship Lab

## Overview
This repository contains the ongoing work for a Detection Engineering internship. The objective of this project is to build a functional SIEM ingestion pipeline, simulate adversary behaviors, and develop custom detection rules using the Sigma standard to identify gaps in default detection rule coverage.

## Lab Architecture
*   **SIEM:** Sekoia.io
*   **Endpoints:** 
    *   Windows Server 2022 (Active Directory Domain Controller)
    *   Windows 11 Pro (CrowdStrike Falcon Endpoint)
    *    (SentinelOne Endpoint)
    *   Entra ID
    *   Fortigate firewall
*   **Attacker Infrastructure:** Kali Linux (Internal Network)

## Repository Structure
*   `/Rules`: Contains all custom Sigma YAML rules, categorized by data source.
*   `/Evidence`: Contains the proof of execution (Sekoia JSON payloads and alert screenshots) for every triggered rule.
*   `Backlog.md`: The living tracking board of 100+ rule candidates mapped to MITRE ATT&CK.


---
*Disclaimer: This repository is a controlled educational lab environment. All attack simulations are performed against authorized, isolated targets.

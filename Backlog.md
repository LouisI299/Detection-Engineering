# Detection Engineering Rule Backlog

This document tracks the rule candidates developed during the internship, mapped to MITRE ATT&CK techniques.

| Data source | Threat behaviour | MITRE ID | Expected Log Evidence | Priority | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Domain Controller** | *Kerberoasting:* Authenticated domain user requests Kerberos ticket for a SPN to obtain password hash for service accounts encrypted with weak algorithms. | T1558.003 | event.id: 4769; TicketEncryptionType: 0x17; Related.User does NOT end with $ | High | **Idea** |
| **Domain Controller** | *Pass the Hash:* Using stolen password hashes to move laterally through an environment. | T1550.002 | eventid: 4624; logontype: 9 (New Credentials); logonprocessname: seclogo | High | **Idea** |
| **Domain Controller** | *Abuse of Domain Accounts:* Abusing obtained domain account credentials to gain unauthorized access to a domain. | T1550.002 | eventid:4624; logontype: 7 or 10 (unlock or remote interactive);  | High | **Idea** |
| **Domain Controller** | *Brute Force - Password Guessing:* Systematically guessing credentials for an account to gain unauthorized access to a domain. | T1110.001 | eventid:4625; 1 Target User | Low | **Idea** |
| **Domain Controller** | *Brute Force - Password Spraying:* Abusing obtained domain account credentials to gain unauthorized access to a domain. | T1110.003 | eventid:4625; Multiple target users  | Medium | **Idea** |
| **Domain Controller** | *Windows Management Instrumentation:* Abuse of WMI to execute malicious commands and payloads. | T1047 | Process cmd/powershell/rundll32/msiexec... with wmic/wmipvrse as parent process OR process: cmd/powershell, command line contains: wmic/InvokeWMIMethod/Invoke-Cimmethod and process call create/os get FORMAT | High | **Idea** |
| **Domain Controller** | *Event Triggered Execution - Windows Management Instrumentation Event Subscription:* Abuse of WMI to subscribe to event and execute code when that event occurs. | T1543.003 | WMI Activity log event (5861); event.message contains "Binding EventFilter" | High | **Idea** |
| **Domain Controller** | *Event Triggered Execution - Windows Management Instrumentation Event Subscription:* Compile WMI scripts using mofcomp.exe to create malicious subscription. | T1543.003 | Process creation event (1); process.name: mofcomp.exe; process.parent: powershell.exe OR file creation event (11); process.name: mofcomp.exe or file.path starts with C:\Windows\System32\wbem\MOF and process name is not trusted_installer.exe  | High | **Idea** |

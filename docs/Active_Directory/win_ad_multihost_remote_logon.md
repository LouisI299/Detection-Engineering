# Windows AD - Multihost Remote Logon

**Rule ID:** 80d72138-06d2-45dd-9db4-5f7ef3bc63f2
**Status:** experimental
**Author / Date:** Louis Ingelbrecht | 2026-05-19

---

## 1. Core Metadata
* **Data Source:** Windows AD DC Security Logs - NXlog
* **MITRE Tactic:** Initial Access/Stealth/Persistence/Privilege Escalation
* **MITRE Technique:** T1078.002 - Valid Accounts: Domain Accounts https://attack.mitre.org/techniques/T1078/002/
* **Severity:** Medium — *Could indicate succesful intrusion by an adversary*
* **Sigma File Path:** `Detection-Engineering\Rules\Active_Directory\win_ad_abuse_of_domain_accounts_t1078_002.yaml`

## 2. Threat Description
Adversary abusing domain account credentials to gain initial access, persistence, privilege escalation or defense evasion, gaining access to the domain's privileged resources.

Could lead to system-wide compromise if the credentials for a high privilege account are obtained. Lower privileged accounts could still be used to move laterally across the system or escalate privileges. Once an attacker has unrestricted access to the system, this could lead to exfiltration/destruction/encryption of sensitive data, ransomware deployment, service obstruction,... 

There are many documented cases of threat actors abusing valid domain accounts to perform malicious activities, such as during the 2025 Poland Wiper Attacks.

## 3. Detection Strategy
* **Detection Logic:** This rule detects succesful interactive or remote login events coming from different source ip's within a short timeframe, which could indicate the account has been compromised.
* **Key Fields Evaluated:**
  * `action.id`: This is how we detect the logon event (4624)
  * `user.target.name`: Determine which account has been compromised.
  * `host.hostname`: What host has the potential adversary gained access on
  * `action.properties.LogonType`: Filtering for only remote/interactive logins
  * `source.ip`: Confirm that the user logged on from multiple networks. Suspicious IP's linked to cloud providers or VPN services could also be a strong indicator of a true positive.

## 4. Execution & Validation
* **How to Trigger:**
  1. Login via RDP from different host, either using different VM's/Machines or changing your IP address after each login. 
* **Trigger Evidence:**
  * **Sekoia Alert ID:** ALmwPxMe6rdq
  * **Timestamp:** 2026-05-19 17:25:31
  * **Screenshot:** (Detection-Engineering\images\multihost-alert.png) 

## 5. Maintenance & Tuning
* **Known False Positives:**
  * /
* **Tuning Notes:**
  * /

## 6. Research Sources
* https://attack.mitre.org/techniques/T1078/002/
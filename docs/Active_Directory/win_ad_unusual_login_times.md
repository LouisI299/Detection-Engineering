# Windows AD - Unusual Login Times

**Rule ID:** c914d548-f2a0-40bc-bc61-4f76d77503e9
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
* **Detection Logic:** This rule detects succesful interactive or remote login events at times where users are not expected to log in, like after working hours, during the weekends, and on bank holidays. This activity could indicate that an external adversary has gained access to a domain user's account, or an insider threat.
* **Key Fields Evaluated:**
  * `action.id`: This is how we detect the logon event (4624)
  * `user.target.name`: Helps filter out machine and service accounts that systematically login at any moment.
  * `action.properties.LogonType`: Filtering for only remote/interactive logins.
  * `timestamp`: Used to tune the specific hours or days that would generate an alert.

## 4. Execution & Validation
* **How to Trigger:**
  1. Login via RDP in the timeframe specified in the rule. (In this case, after 5PM on a weekday)
* **Trigger Evidence:**
  * **Sekoia Alert ID:** AL5vU19S4wJL
  * **Timestamp:** 2026-05-19 17:38:33
  * **Screenshot:** (Detection-Engineering\images\unusual-login-alert.png) 

## 5. Maintenance & Tuning
* **Known False Positives:**
  * An employee working overtime, or on weekends/holidays
  * Machine/service account not included in the filters
* **Tuning Notes:**
  * The relevant timezone, working hours, machine and service accounts and other exceptions should be tuned to avoid false positives

## 6. Research Sources
* https://attack.mitre.org/techniques/T1078/002/
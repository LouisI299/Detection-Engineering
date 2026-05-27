# Windows AD - Pass the Hash

**Rule ID:** 070eaef5-4b4b-4f59-b247-cdfd00290d6b
**Status:** experimental
**Author / Date:** Louis Ingelbrecht | 2026-05-18

---

## 1. Core Metadata
* **Data Source:** Windows AD DC Security Logs - NXlog
* **MITRE Tactic:** Initial Access/Stealth/Persistence/Privilege Escalation
* **MITRE Technique:** T1550.002 - Use Alternate Authentication Material: Pass the Hash https://attack.mitre.org/techniques/T1550/002/
* **Severity:** Medium — *Could indicate succesful intrusion by an adversary*
* **Sigma File Path:** `Detection-Engineering\Rules\Active_Directory\win_ad_pass_the_hash_t1550_002.yaml`

## 2. Threat Description
Authenticating as a user using the password hash, usually obtained through Kerberoasting or other Credential Access techniques. Usually facilitated by tools like rubeus and mimikatz.

Could allow an adversary to move laterally across systems.

There are many documented cases of threat actors abusing valid domain accounts to perform malicious activities, such as during the 2025 Poland Wiper Attacks.

## 3. Detection Strategy
* **Detection Logic:** This rule detects either a logon event type 9, with process name seclogo or a 4768 event (TGT request) with encryption type 0x17 (RC4 / Old encryption).
* **Key Fields Evaluated:**
  * `action.id`: This is how we detect the logon or TGT event (4624 or 4768)
  * `action.properties.LogonProcessName`: Helps identify seclogo process
  * `action.properties.LogonType`: Filtering for logon type 9
  * `action.properties.TicketEncryptionType`: Helps detect old encryption being used when logging on.

## 4. Execution & Validation
* **How to Trigger:**
  1. Use Rubeus to get password hash: ~ .\rubeus.exe hash /password:<password>
  2. Use Rubeus to perform TGT request: ~ .\rubeus.exe asktgt /user:<target-user> /domain:<domain> /rc4:<hash> /ptt
* **Trigger Evidence:**
  * **Sekoia Alert ID:** ALWccfa6Ssg2
  * **Timestamp:** 2026-05-20 13:57:44
  * **Screenshot:** (Detection-Engineering\images\pass-the-hash-hash.png) (Detection-Engineering\images\pass-the-hash-tgt.png) (Detection-Engineering\images\pass-the-hash-alert.png)

## 5. Maintenance & Tuning
* **Known False Positives:**
  * An outdated/legacy service running on RC4 encryption
* **Tuning Notes:**
  * Trusted services using RC4 encryption should be filtered

## 6. Research Sources
* https://attack.mitre.org/techniques/T1550/002/
* 
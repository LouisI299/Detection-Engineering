# Windows AD - Domain Account Discovery

**Rule ID:** df92d29e-a57b-422a-a128-8594d72fdd02/ 8f9ba4cc-6b81-49a0-a680-c2434768d773
**Status:** experimental
**Author / Date:** Louis Ingelbrecht | 2026-05-19

---

## 1. Core Metadata
* **Data Source:** Windows AD DC Security Logs - NXlog
* **MITRE Tactic:** Discovery
* **MITRE Technique:** T1087.002 - Account Discovery: Domain Account https://attack.mitre.org/techniques/T1087/002/
* **Severity:** Medium — *Indicates attempts at mapping out AD Structure*
* **Sigma File Path:** `Detection-Engineering\Rules\Active_Directory\win_ad_process_1m_account_discovery_domain_account_t1087.yaml`
`Detection-Engineering\Rules\Active_Directory\win_ad_script_1m_account_discovery_domain_account_t1081.yaml`

## 2. Threat Description
Adversaries can use built-in commands/powershell scripts to retrieve information about domain users, groups, privileges,...

This information can then be used to decide which high-privileged/service accounts to target.

Adversary groups such as APT41 and BRONZE BUTLER used "net" commands to enumerate domain administrator users.

## 3. Detection Strategy
* **Detection Logic:** Given the fact that these commants and powershell tools are commonly used by administrators, this rule detects multiple executions within a short timeframe, indicating attempts at domain account discovery. Use of these commands by non-admin users is also seen as suspicious, but not included in this rule because only administrators can logon to this AD Domain Controller.
* **Key Fields Evaluated:**
  * `action.id`: Detect process creation (1) or powershell script execution (4104) events.
  * `process.name`: Detects the creation of processes such as net, nltest, and dsquery.
  * `action.properties.ScriptBlockText`: Detect powershell tools such as Get-AD or Search-AD

## 4. Execution & Validation
* **How to Trigger:**
  1. Execute 5 or more domain enumeration commands/scripts within 1 minute.
* **Trigger Evidence:**
  * **Sekoia Alert ID:** AL4Ky23JchHC/ALzvbJYDFqpm
  * **Timestamp:** 2026-05-20 14:11:43 / 2026-05-20 15:32:56
  * **Screenshot:** (Detection-Engineering\images\domain-user-cmd.png) (Detection-Engineering\images\domain-user-cmd-alert.png) (Detection-Engineering\images\domain-user-ps.png) (Detection-Engineering\images\domain-user-ps-alert.png)

## 5. Maintenance & Tuning
* **Known False Positives:**
  * Legitimate use for administrative purposes
* **Tuning Notes:**
  * ?

## 6. Research Sources
* https://attack.mitre.org/techniques/T1087/002/
* https://lolad-project.github.io/
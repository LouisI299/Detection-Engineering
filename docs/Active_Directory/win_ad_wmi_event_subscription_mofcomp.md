# Windows AD - WMI Event Subscription - Mofcomp

**Rule ID:** ad81470f-594d-48a3-8823-dbd9778c37c4
**Status:** experimental
**Author / Date:** Louis Ingelbrecht | 2026-05-19

---

## 1. Core Metadata
* **Data Source:** Windows AD DC Security Logs - NXlog
* **MITRE Tactic:** Initial Access/Stealth/Persistence/Privilege Escalation
* **MITRE Technique:** T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription https://attack.mitre.org/techniques/T1546/003/
* **Severity:** Medium — *Indicates escalation of privileges*
* **Sigma File Path:** `Detection-Engineering\Rules\Active_Directory\win_ad_filecreation_event_triggered_execution_t1546_003.yaml`

## 2. Threat Description
Adversaries can compile WMI scripts into Windows Management Object files using mofcomp.exe to create malicious event subscriptions. 

These events are triggered under the wmiprvse process which runs on SYSTEM privileges, allowing them to escalate privileges.

Blue Mockingbird malware uses mofcomp.exe to create malicious WMI Event Subscriptions.

## 3. Detection Strategy
* **Detection Logic:** This rule detects file creation events made by the process mofcomp.exe or files made inside the MOF folder. Some legitimate programs exhibit this same kind of behavior, so this rule needs to be tuned to the organisation's environment.
* **Key Fields Evaluated:**
  * `action.id`: Detect file creation event (11)
  * `process.name`: Detect files created by process mofcomp.exe, and filtering out legitimate processes
  * `file.path`: Detect files created inside MOF folder

## 4. Execution & Validation
* **How to Trigger:**
  1. Triggered using Atomic Red Team automatic test (T1546.003-3)
* **Trigger Evidence:**
  * **Sekoia Alert ID:** ALjk1nUmS7ie
  * **Timestamp:** 2026-05-20 14:55:07
  * **Screenshot:** (Detection-Engineering\images\mofcomp-test.png) (Detection-Engineering\images\mofcomp-alert.png) 

## 5. Maintenance & Tuning
* **Known False Positives:**
  * Legitimate services creating MOF Files
* **Tuning Notes:**
  * Identify and filter out legitimate services that create MOF files

## 6. Research Sources
* https://attack.mitre.org/techniques/T1546/003/
* https://cyberbuff.github.io/TheAtomicPlaybook/tactics/privilege-escalation/T1546.003.html
# Windows AD - WMI Event Subscription - Mofcomp Process

**Rule ID:** db57f33c-5a4c-4c35-a799-8220f6fb335b
**Status:** experimental
**Author / Date:** Louis Ingelbrecht | 2026-05-18

---

## 1. Core Metadata
* **Data Source:** Windows AD DC Security Logs - NXlog
* **MITRE Tactic:** Privilege Escalation
* **MITRE Technique:** T1546.003 - Event Triggered Execution: Windows Management Instrumentation Event Subscription https://attack.mitre.org/techniques/T1546/003/
* **Severity:** Medium — *Indicates escalation of privileges*
* **Sigma File Path:** `Detection-Engineering\Rules\Active_Directory\win_ad_process_event_triggered_execution_t1546_003.yaml`

## 2. Threat Description
Adversaries can compile WMI scripts into Windows Management Object files using mofcomp.exe to create malicious event subscriptions. 

These events are triggered under the wmiprvse process which runs on SYSTEM privileges, allowing them to escalate privileges.

Blue Mockingbird malware uses mofcomp.exe to create malicious WMI Event Subscriptions.

## 3. Detection Strategy
* **Detection Logic:** This rule detects mofcomp.exe process creation by tools like Powershell.
* **Key Fields Evaluated:**
  * `action.id`: Detect process creation event (1)
  * `process.name`: Detect mofcomp process
  * `process.parent.name`: Detect process being started by powershell

## 4. Execution & Validation
* **How to Trigger:**
  1. Triggered using Atomic Red Team automatic test (T1546.003-3)
* **Trigger Evidence:**
  * **Sekoia Alert ID:** AL7vxU8hTnzK
  * **Timestamp:** 2026-05-20 14:55:12
  * **Screenshot:** (Detection-Engineering\images\mofcomp-test.png) (Detection-Engineering\images\mofcomp-process-alert.png) 

## 5. Maintenance & Tuning
* **Known False Positives:**
  * ?
* **Tuning Notes:**
  * ?

## 6. Research Sources
* https://attack.mitre.org/techniques/T1546/003/
* https://cyberbuff.github.io/TheAtomicPlaybook/tactics/privilege-escalation/T1546.003.html
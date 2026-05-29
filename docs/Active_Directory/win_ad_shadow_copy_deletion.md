# Windows AD - Shadow Copy Deletion (Process / Powershell Script / WMI)

**Rule ID:** 2e3c3d3f-a25a-473a-a5b8-3dcb3d30b1c5 / 210dee09-b3e3-4389-a67e-f7e572758b0a / 208b3a64-c966-4099-8532-62b97c849f4d
**Status:** experimental
**Author / Date:** Louis Ingelbrecht | 2026-05-18

---

## 1. Core Metadata
* **Data Source:** Windows AD DC Security Logs - NXlog
* **MITRE Tactic:** Execution/Impact
* **MITRE Technique:** T1490 - Inhibit System Recovery https://attack.mitre.org/techniques/T1490/
* **Severity:** High — *Indicates deletion of shadow copies to inhibit the recovery of a corrupted system (e.g. by a ransomware attack)*
* **Sigma File Path:** `Detection-Engineering\Rules\Active_Directory\win_ad_process_inhibit_system_recovery_T1490.yaml`
`Detection-Engineering\Rules\Active_Directory\win_ad_script_inhibit_system_recovery_T1490.yaml`
`Detection-Engineering\Rules\Active_Directory\win_ad_wmi_inhibit_system_recovery_T1490.yaml`

## 2. Threat Description
Adversaries can use commandline tools, powershell scripts or wmi to delete volume shadow copies on a system.

This makes it harder for an organization to recover after Data Destruction (T1485) or Data Encryption (T1486).

This technique was applied during the 2025 Poland Wiper Attacks, and many known Ransomware tools offer this function.

## 3. Detection Strategy
* **Detection Logic:** This detection is split up in 3 different rules, to detect shadow copy deletion via process creation (usually via commandline), powershell scripts, or Windows Management Instrumentation.
* **Key Fields Evaluated:**
  * `action.id`: Detect process creation event (1), powershell script execution (4104), or wmi event (5857).
  * `process.name`: Detect execution of shadow volume admin tools like vssadmin or diskshadow.
  * `process.Command_Line`: Detects strings like "delete shadows" or "quiet" being entered in the command line
  * `process.Command_Line`: Detects strings like "delete shadows" or "quiet" being entered in the command line

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
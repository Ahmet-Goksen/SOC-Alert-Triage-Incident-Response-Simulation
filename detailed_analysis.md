# SOC Alert Triage & Incident Response Simulation

## Scenario

Acting as a Tier 1 SOC Analyst, I triaged multiple security alerts in a simulated enterprise environment by determining true/false positives and documenting findings appropriately.

**Objective:** To demonstrate proficiency in real-world SOC operations including alert triage, investigation using a SOAR platform, false positive identification, and proper incident documentation.

## Tools & Technologies Used

**Primary Platform:**
*   SOAR/SOC Case Management Platform (Simulator)

**Integrated Security Tools (Simulated):**
*   Email Security Gateway
*   Endpoint Detection and Response (EDR)
*   Splunk - Security Information and Event Management (SIEM)

**Analyst Tools & Techniques:**
*   Alert Triage Workflow Systems
*   Threat Intelligence Integration
*   Incident Response Playbooks
*   Case Documentation Templates

## Methodology & Key Alerts Triaged

### Initial Alert Assessment & Prioritization
*   Upon login to the SOC platform, I reviewed the alert queue and applied the following prioritization model: **Severity → Time → Type**.
*   Began the investigation with the oldest alert (ID: 1000).

### Alert #1000 - Phishing Email Attempt Investigation (Example Workflow)
*   **Alert Details:** "Suspicious email from external domain" with sender `eileen@trendymillineryco.me`.
*   **Investigation Steps:**
    1.  Reviewed email headers and content via the integrated case management system.
    2.  Identified classic phishing indicators:
        *   Unusual TLD (`.me` for a supposed business).
        *   Urgent financial solicitation ("inheritance" claim).
        *   Request for banking details.
        *   Lack of legitimate business context for recipient domain (`tryhatme.com`).
    3.  Verified no malicious attachments were present.
*   **Conclusion:** True Positive - Clear Phishing (T1566) attempt.
*   **Action Taken:** Documented IOC (sender email), recommended blocking sender domain, and suggested user awareness training.

### Process Alert Pattern Recognition
*   Noticed multiple "Suspicious Parent Child Relationship" alerts (IDs: 1001, 1002, etc.).
*   Applied correlation analysis: Both occurred within a 5-minute window, with similar low severity.
*   The relationship `svchost.exe → taskhostw.exe` is completely normal:
    *   `svchost.exe` manages Windows services.
    *   When certain DLL-based services need to run, they spawn `taskhostw.exe`.
*   **Hypothesis:** Likely related to a legitimate scheduled task or software update causing benign detections.
*   **Decision:** Reported as false positives and recommended rule tuning.
*   Handled all other similar non-malicious process alerts using the same methodology.

### Spam Email Alert Pattern Recognition
*   Noticed multiple "Suspicious email from external domain" alerts (IDs: 1003, 1004, 1011, etc.).
*   The SOC Lead's note indicated this rule "still needs fine-tuning," suggesting a known high false positive rate.
*   Analysis revealed no malicious intent:
    *   No credential harvesting attempts.
    *   No financial fraud elements.
    *   No malicious attachments or embedded links.
    *   No impersonation of trusted entities.
    *   No urgency or fear tactics.
    *   Emails offered products/services (commercial spam).
*   **Hypothesis:** These alerts represent unsolicited commercial email (spam) rather than malicious phishing attempts.
*   **Decision:** Reported as false positives, recommended rule tuning and adding sender domains to the spam filter.

### Alert #1005 - Beginning of Attacker Infiltration
*   **Alert Details:** "Suspicious attachment found in email" from sender `john@hatmakereurope.xyz` to recipient `michael.ascot@tryhatme.com`.
*   **Investigation Steps:**
    1.  Reviewed email headers and content.
    2.  Identified phishing indicators:
        *   Unusual TLD (`.xyz`).
        *   Use of urgency: *"Open the attached invoice immediately to view payment options and avoid legal consequences."*
    3.  Used integrated threat intelligence to verify the attachment (`ImportantInvoice-Febrary.zip`) was malicious.
    4.  Subsequent alerts supported the phishing hypothesis.
*   **Conclusion:** True Positive - Initial access Phishing (T1566) and User Execution (T1204) attempt.
*   **Action Taken:** Documented IOCs, escalated to SOC L2, recommended blocking sender domain and user awareness training.

### Alert #1020 - Follow-up to Initial Compromise
*   **Alert Details:** "PowerShell Script in Downloads Folder" on host `win-3450` for user `michael.ascot`.
*   File created: `C:\Users\michael.ascot\Downloads\PowerView.ps1`.
*   **Investigation Steps:**
    1.  Correlated with previous Incident #1005 involving the same user.
    2.  Identified `PowerView.ps1` as a well-known tool for Active Directory reconnaissance.
    3.  Analyzed the timeline:
        *   10:58: Phishing email received (Alert #1005).
        *   11:22: `PowerView.ps1` created.
    4.  Checked contextual indicators:
        *   Created by PowerShell process (PID 9060).
        *   No legitimate business need for this tool in a user's Downloads folder.
    5.  Verified via threat intelligence that PowerView is part of the PowerSploit framework.
*   **Conclusion:** True Positive - Post-compromise activity indicating successful initial access and beginning of reconnaissance.
*   **MITRE ATT&CK Mapping:** T1059.001 (PowerShell), T1087 (Account Discovery), T1204 (User Execution).
*   **Actions Taken:**
    *   Urgent notification to SOC L2 and IR team.
    *   Documented IOCs (user, host, timestamps).
    *   Initiated threat hunting for lateral movement.
*   **Recommended Action:** Isolate host `win-3450` and disable user `michael.ascot`'s account.

### Alert #1022 - Lateral Movement and Data Discovery
*   **Alert Details:** "Network drive mapped to a local drive" on compromised host `win-3450`.
*   Activity: Mapped `Z:` → `\\FILESRV-01\SSF-FinancialRecords`.
*   **Investigation Steps:**
    1.  Correlated with Alerts #1005 and #1020.
    2.  Identified suspicious context: `net.exe` executed via malicious PowerShell.
    3.  Analyzed timeline progression (following `PowerView.ps1` creation).
    4.  Determined abnormal behavior (drives not typically mapped via PowerShell from Downloads).
    5.  Verified target sensitivity (`SSF-FinancialRecords`).
*   **Conclusion:** True Positive - Lateral Movement and Data Access.
*   **MITRE ATT&CK Mapping:** T1021.002 (SMB), T1039 (Data from Network Share), T1570 (Lateral Tool Transfer).
*   **Actions Taken:** Escalated, documented IOCs (including command line).
*   **Recommended Action:** Terminate sessions to `FILESRV-01`, confirm host isolation, preserve logs.

### Alert #1023 - Data Collection and Exfiltration Preparation
*   **Alert Details:** "Suspicious Parent Child Relationship" on host `win-3450`.
*   Activity: `Robocopy.exe` executed from PowerShell to copy `Z:\` to `C:\Users\michael.ascot\downloads\exfiltration\`.
*   **Investigation Steps:**
    1.  Correlated with ongoing incident (post drive mapping).
    2.  Confirmed same malicious PowerShell parent process (PID 3728).
    3.  Analyzed `Robocopy` command with `/E` switch (copy all subdirectories).
    4.  Noted explicit folder name `exfiltration` indicating malicious intent.
*   **Conclusion:** True Positive - Data Staging for Exfiltration.
*   **MITRE ATT&CK Mapping:** T1005, T1020, T1560, T1074.001.
*   **Actions Taken:** Blocked outbound traffic from host, created forensic images, elevated severity to Critical.
*   **Recommended Actions:** Scan `FILESRV-01`, assess data loss, review user access, hunt for exfiltration.

### Alert #1024 - Attacker Cleanup and Operational Security
*   **Alert Details:** "Network drive disconnected from a local drive" on host `win-3450`.
*   Activity: `net.exe` used with command `use Z: /delete`.
*   **Investigation Steps:**
    1.  Correlated timing (11 seconds after data staging).
    2.  Confirmed same attacker-controlled PowerShell process.
    3.  Recognized command as standard cleanup.
    4.  Assessed as operational security (OpSec) to remove evidence.
*   **Conclusion:** True Positive - Defense Evasion and Attack Progression.
*   **MITRE ATT&CK Mapping:** T1070.004 (Indicator Removal), T1202 (Indirect Command Execution).
*   **Actions Taken:** Finalized attack timeline, prioritized RAM capture for forensics.
*   **Recommended Actions:** Consider power isolation of host, perform memory forensics, expand investigation scope.

### Alerts #1025-1034 - Active Data Exfiltration Phase
*   **Alert Details:** Multiple "Suspicious Parent Child Relationship" alerts.
*   Activity: Nine instances of `nslookup.exe` spawned by malicious PowerShell from the `exfiltration` directory.
*   **Key Observations:**
    1.  **Technique:** DNS exfiltration/tunneling to attacker-controlled domain `haz4rdw4re.io`.
    2.  **Data Encoding:** Base64-like strings appended to subdomains (e.g., containing "ClientPortfolio", "Summary.xlsx").
    3.  **Progression:** Confirmed completion of attack chain: Phishing → Theft → Movement → Collection → Staging → Exfiltration.
    4.  **Timing:** All alerts at `01/01/2026 22:45:23`.
*   **Conclusion:** Critical True Positive - Data Exfiltration in Progress.
*   **MITRE ATT&CK Mapping:** T1048.003 (Exfiltration over DNS), T1071.004 (DNS Protocol), T1560.001 (Archive via Utility).
*   **Actions Taken:** Elevated to Critical severity, initiated full IR protocol, documented critical IOCs.
*   **Recommended Actions:**
    *   DNS blocking of `haz4rdw4re.io`.
    *   Full network isolation of `win-3450`.
    *   Emergency DNS log analysis network-wide.
    *   Formal incident declaration and data breach assessment.
    *   Forensic preservation and attack reconstruction.

**Conclusion:** The organization was compromised via a phishing email, leading to a multi-stage attack involving credential theft, lateral movement to a financial server, data staging, and exfiltration via DNS tunneling. The incident demonstrates a complete intrusion lifecycle.

## Overall Takeaways

This investigation highlighted essential principles of effective SOC analysis and incident response:

*   **Context separates noise from threats:** The majority of alerts were false positives—benign processes or spam. Accurate triage required correlating events with system knowledge and business context.
*   **Correlation reveals the attack chain:** Isolated alerts became significant only when linked by the compromised user and host, reconstructing the kill chain.
*   **Understanding attacker tradecraft enables prediction:** Mapping events to the MITRE ATT&CK framework provided a model of adversary behavior, guiding response.
*   **Impact dictates response priority:** The investigation correctly escalated when activity shifted to high-value assets (financial records), focusing on mitigating real business risk.

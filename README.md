# SOC Alert Triage & Incident Response Simulation

## Objective
Act as a Tier 1 SOC Analyst to triage a high-volume alert queue, distinguish malicious threats from false positives, and contain a sophisticated, multi-stage attack leading to data exfiltration.

## Core Scenario
A simulated phishing email led to a full intrusion chain:
**Initial Compromise → Credential Theft → Lateral Movement → Data Staging → Active DNS Exfiltration.**

## Tools & Platforms
*   **SOAR/SOC Case Management Simulator**
*   **Splunk** (SIEM)
*   Threat Intelligence Feeds
*   **MITRE ATT&CK Framework**

## Key Achievements & Metrics
*   **100% True Positive Identification:** Correctly identified every stage of a live attack chain, from initial phishing to data exfiltration.
*   **39% Faster Response:** Contained the threat with a **27-minute incident dwell time**, a **39% improvement** over prior simulation benchmarks.
*   **Effective Triage:** Efficiently processed a high-volume alert queue, correctly classifying **49% of alerts as false positives** through pattern recognition and context analysis.
*   **Full Attack Chain Analysis:** Mapped attacker actions to the MITRE ATT&CK framework, demonstrating understanding of adversary tradecraft from **Initial Access (T1566) to Exfiltration (T1048).**

## Attack Narrative Summary
1.  **Initial Compromise:** Identified a phishing email with a malicious attachment as the entry point.
2.  **Internal Reconnaissance:** Detected post-compromise execution of `PowerView.ps1` for Active Directory discovery.
3.  **Lateral Movement & Data Access:** Correlated alerts to uncover attacker movement to a file server containing sensitive financial records.
4.  **Exfiltration:** Identified and halted active data theft using DNS tunneling to an attacker-controlled domain.

## Skills Demonstrated
*   **Alert Triage & Prioritization:** Applied a severity-time-type model to a busy SOC queue.
*   **Incident Correlation:** Connected discrete alerts across systems to build a narrative of the attack.
*   **False Positive Reduction:** Recognized patterns of benign activity (e.g., normal Windows processes, spam).
*   **Incident Response:** Executed containment actions (host isolation, DNS blocking) and followed escalation procedures.
*   **Professional Documentation:** Maintained clear case notes with IOCs and MITRE ATT&CK mappings.

---
**See the full technical analysis:** [detailed_analysis.md]

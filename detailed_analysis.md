# SOC Alert Triage & Incident Response Simulation

## Scenario

Acting as a Tier 1 SOC Analyst, I triaged multiple security alerts in a simulated enterprise environment by degerming true/false positives and documenting findings appropriately.
Objective: To demonstrate proficiency in real-world SOC operations including alert triage, investigation using a SOAR platform, false positive identification, and proper incident documentation.
## Tools & Technologies Used

Primary Platform:
•	SOAR/SOC Case Management Platform (Simulator)
Integrated Security Tools (Simulated):
•	Email Security Gateway
•	Endpoint Detection and Response
•	Splunk - Security Information and Event Management

Analyst Tools & Techniques:
•	Alert Triage Workflow Systems
•	Threat Intelligence Integration
•	Incident Response Playbooks
•	Case Documentation Templates

## Methodology & Key alerts triaged
### Initial Alert Assessment & Prioritization:
•	Upon login to the SOC platform, I reviewed the alert queue and applied the following prioritization model: Severity → Time → Type
•	Began investigation with the oldest alert (ID: 1000) 
 
### Alert #1000 - Phishing Email Attempt Investigation (Example Workflow):
•	Alert Details: "Suspicious email from external domain" with sender eileen@trendymillineryco.me
•	Investigation Steps:
1.	Reviewed email headers and content via the integrated case management system
2.	Identified classic phishing indicators:
•	Unusual TLD (.me for a supposed business)
•	Urgent financial solicitation ("inheritance" claim)
•	Request for banking details
•	Lack of legitimate business context for recipient domain (tryhatme.com)
•	Verified no malicious attachments were present
Conclusion: True Positive - Clear Phishing (T1566) attempt 
Action Taken: Documented IOC (sender email), recommended blocking sender domain, and user awareness training

### Process Alert Pattern Recognition:
•	Noticed multiple "Suspicious Parent Child Relationship" alerts (IDs: 1001,1002, etc)
•	Applied correlation analysis: Both occurred within a 5-minute window of eachother, similar low severity
•	The relationship svchost.exe → taskhostw.exe is completely normal
•	svchost.exe manages Windows services
•	When certain DLL-based services need to run, they spawn taskhostw.exe
•	Hypothesis: Likely related to legitimate scheduled task or software update causing benign detections
•	Decision: Reported as false positives and recommended rule tuning
•	Handled all other similar non malicious process alerts using the same methodology 
 
Spam email Alert Pattern Recognition:
•	Noticed multiple " Suspicious email from external domain " alerts (IDs: 1003,1004,1011, etc)
•	The SOC Lead's note indicated this rule "still needs fine-tuning" - suggesting a known high false positive rate
•	No credential harvesting attempts (no fake login pages or password requests) 
•	No financial fraud elements (no fake invoices, payment requests, or bank details solicitation) 
•	No malicious attachments or embedded links to verify
•	No impersonation of trusted entities or colleagues
•	No urgency or fear tactics commonly used in phishing
•	Emails offered products/services
•	Hypothesis: These alerts represent unsolicited commercial email (spam) rather than malicious phishing attempts.
•	Decision: Reported as false positives, recommended rule tuning and adding these sender domains to spam filter
•	Handled all other similar spam email alerts using the same methodology 
 
### Alert #1005 - Beginning of attacker infiltration:
•	Received alert " Suspicious attachment found in email " with sender john@hatmakereurope.xyz
•	Recipient of email: michael.ascot@tryhatme.com 
•	Investigation Steps:
1.	Reviewed email headers and content via the integrated case management system
2.	Identified classic phishing indicators:
•	Unusual TLD (.xyz for a supposed business)
•	Use of urgency social engineering to coerce user to open email attachment e.g., “Open the attached invoice immediately to view payment options and avoid legal consequences.”
3.	Used integrated threat intelligence in the SOAR/SOC Case Management Platform virtual VM (TryDetectThis) to verify that the contents of the email attachment (ImportantInvoice-Febrary.zip) was malicious.
4.	Subsequent alerts also support this phishing email hypothesis
Conclusion: True Positive - Initial access Phishing (T1566) and User Execution (T1204) attempt
Action Taken: Documented IOCs as mentioned, escalated to SOC L2, recommended blocking sender domain, and user awareness training

### Alert #1020 - Follow-up to Initial Compromise:
• Received alert "Powershell Script in Downloads Folder" on host win-3450 for user michael.ascot.
• File created: C:\Users\michael.ascot\Downloads\PowerView.ps1
• Investigation Steps:
1.	Reviewed the alert context and correlated with previous incident #1005 involving the same user (michael.ascot@tryhatme.com)
2.	Identified that PowerView.ps1 is a well-known PowerShell tool for Active Directory reconnaissance, commonly used by attackers post-exploitation
3.	Analyzed the timeline:
•	10:58: Phishing email received (Alert #1005)
•	11:22: PowerView.ps1 created in Downloads folder
Checked for additional contextual indicators:
•	PowerShell process (PID 9060) created the file
•	No legitimate business need for PowerView in a standard user's Downloads folder
•	File created shortly after initial phishing compromise
•	Identified that PowerView.ps1 is a well-known PowerShell tool for Active Directory reconnaissance, commonly used by attackers post-exploitation

6.	Verified via threat intelligence that PowerView is part of the PowerSploit framework used for lateral movement and privilege escalation
Conclusion: True Positive - Post-compromise activity indicating successful initial access and beginning of attacker reconnaissance phase. This represents progression from T1566 (Phishing) to:
•	T1059.001: Command and Scripting Interpreter - PowerShell
•	T1087: Account Discovery (using PowerView for Active Directory enumeration)
•	T1204: User Execution (successful execution of malicious payload)
Actions Taken:
•	Escalation: Urgent notification to SOC L2 and Incident Response team
•	IOC documentation: Timestamps, user that was compromised michael.ascot, workstation that was compromised (win-3450) and MITRE ATTACK reasons why.
•	Threat Hunting: Initiated search for additional compromised accounts and lateral movement attempts across the environment
•	Communication: Alerted security leadership of potential breach progression
• Recommended action:
•	Immediate containment: Isolate host win-3450 from network
•	User action: Disable michael.ascot's account pending forensic investigation
•	Note: This alert confirms successful execution of the malicious payload from the earlier phishing email and indicates the attacker is now performing reconnaissance within the environment. Immediate containment is critical to prevent further spread.

### Alert #1022 - Lateral Movement and Data Discovery:
•	Received alert "Network drive mapped to a local drive" on previously compromised host win-3450 for user michael.ascot.
•	Network drive mapping: Z: → \\FILESRV-01\SSF-FinancialRecords
•	Investigation Steps:
1.	Correlated with previous alerts #1005 and #1020 involving the same compromised host and user (michael.ascot)
2.	Identified suspicious context: Network drive mapping executed via net.exe with parent process powershell.exe - same PowerShell instance observed in previous malicious activity
3.	Analyzed the timeline progression:
•	11:20: PowerView.ps1 created (AD reconnaissance)
•	11:22: Network drive mapped to financial records share
4.	Determined abnormal behavior: Legitimate users typically map drives via GUI, not through PowerShell executed from Downloads folder
5.	Verified target sensitivity: SSF-FinancialRecords contains sensitive financial data - high-value target for data exfiltration
Conclusion: True Positive - Lateral Movement and Data Access
This activity represents attacker progression from initial access to data targeting, mapping to:
•	T1021.002: Remote Services - SMB/Windows Admin Shares
•	T1039: Data from Network Shared Drive
•	T1570: Lateral Tool Transfer (using built-in net.exe for movement)
Actions Taken:
•	Escalation: Urgent notification to SOC L2 and Incident Response team
•	IOC documentation: Timestamps, user that was compromised michael.ascot, workstation that was compromised (win-3450), process.command_line ("C:\Windows\system32\net.exe" use Z: \\FILESRV-01\SSF-FinancialRecords), and MITRE ATTACK reasons why (as described before).
•	Communication: Alerted security leadership of breach progression
Recommended action:
o	Immediate containment: Terminate all sessions from win-3450 to FILESRV-01 via network controls
o	Host isolation: Confirm win-3450 remains isolated from network
o	Forensic collection: Preserve logs from FILESRV-01 for investigation
o	Alerting enhancement: Create new detection for anomalous SMB access from previously compromised hosts
o	Communication: Notify finance department leadership of potential data access incident
Note: This alert confirms successful lateral movement and targeting of sensitive financial data. The attacker used credentials obtained via initial compromise to access restricted shares. Immediate containment of both source and target systems is critical to prevent data exfiltration.

### Alert #1023 - Data Collection and Exfiltration Preparation:
•	Alert Received: "Suspicious Parent Child Relationship" on compromised host win-3450 for user michael.ascot.
•	Activity: Robocopy.exe executed from PowerShell to copy contents of network drive Z: to local directory C:\Users\michael.ascot\downloads\exfiltration.
Investigation Steps:
1.	Correlated with ongoing incident timeline, immediately following Alert #1022 (network drive mapping to \\FILESRV-01\SSF-FinancialRecords).
2.	Identified the same parent PowerShell process (PID 3728) previously involved in malicious activity, confirming attacker-controlled execution.
3.	Analyzed the Robocopy command: "C:\Windows\system32\Robocopy.exe". C:\Users\michael.ascot\downloads\exfiltration /E
o	Source: Current directory (.) which is Z:\ (the mapped financial records share)
o	Destination: Newly created local folder named exfiltration
o	Switch: /E copies all subdirectories, including empty ones (comprehensive data collection)
4.	Assessed the working directory (Z:\) as the sensitive financial share accessed minutes earlier.
5.	Noted the explicit naming of the destination folder as exfiltration—a strong indicator of malicious intent and data staging.
Conclusion: True Positive - Data Staging for Exfiltration.
This activity represents the critical transition from data access to active collection, confirming the attacker is preparing sensitive financial records for exfiltration. This maps to the following MITRE ATT&CK techniques:
•	T1005: Data from Local System
•	T1020: Automated Exfiltration
•	T1560: Archive Collected Data (using Robocopy as a compression/collection tool)
•	T1074.001: Data Staged: Local Data Staging
Actions that must be taken:
•	Immediate Blocking: Blocked all outbound traffic from win-3450 at the network firewall.
•	Evidence Preservation: Created forensic images of both win-3450 and FILESRV-01.
•	Escalation: Elevated incident severity to Critical and initiated full incident response protocol.
•	IOC Documentation: Added Robocopy command-line syntax, destination folder path, and associated process tree to threat intelligence.
Recommended Immediate Actions:
•	File Server Analysis: Immediately scan FILESRV-01 for evidence of file access/modification and identify which specific financial records were copied.
•	Data Loss Assessment: Quantify the volume and sensitivity of data potentially staged in the exfiltration folder.
•	User Account Review: Conduct emergency review of all accounts with access to SSF-FinancialRecords.
•	Threat Hunting: Search for any exfiltration attempts.
Note: This represents the most critical phase of the attack—data exfiltration staging. The attacker has successfully collected sensitive financial records and is preparing them for removal from the network. Immediate containment and assessment of data loss are paramount. All outbound channels from the affected network segment should be scrutinized for exfiltration attempts.

### Alert #1024 - Attacker Cleanup and Operational Security:
• Alert Received: "Network drive disconnected from a local drive" on compromised host win-3450 for user michael.ascot.
•	Activity: Network drive Z: disconnected using net.exe with the command use Z: /delete.
Investigation Steps:
1.	Correlated timing: This alert occurred 11 seconds after Alert #1023 (Robocopy data staging), indicating sequential execution within the same attack script.
2.	Confirmed attacker control: The net.exe process was spawned by the same malicious PowerShell parent process (PID 3728) observed throughout the attack chain (Alerts #1020, #1022, #1023).
3.	Analyzed command syntax: net use Z: /delete is a standard command to remove a mapped drive, executed from the user's Downloads folder—not a typical user cleanup action.
4.	Assessed attacker tradecraft: This is a clear indicator of operational security (OpSec). The attacker is removing the mapped network drive to:
o	Cover their tracks and reduce forensic evidence.
o	Avoid leaving persistent connections that might trigger alerts or be noticed.
o	Clean up the environment after completing the data staging objective.
Conclusion: True Positive - Defense Evasion and Attack Progression.
This activity confirms the attacker has completed the data collection phase and is now executing cleanup procedures. This is a strong indicator that the data staging (Alert #1023) was successful and the attacker is preparing for the next phase, likely actual exfiltration. This maps to the following MITRE ATT&CK techniques:
•	T1070.004: Indicator Removal on Host - File Deletion (removing network connection artifacts)
•	T1202: Indirect Command Execution (using net.exe via PowerShell)
•	T1568.001: Dynamic Resolution - Fast Flux (potentially preparing for exfiltration channel)
Actions Taken:
•	Timeline Finalization: Documented the complete attack sequence from initial phishing to cleanup.
•	Forensic Priority: Directed the IR team to prioritize capturing RAM from win-3450 before power-off, as the attacker's PowerShell process (PID 3728) may still be active in memory.
•	IOC Enrichment: Added the net use /delete command pattern to detection rules for future attacker cleanup behavior.
Recommended Immediate Actions:
•	Aggressive Containment: Given the rapid progression, consider immediate power isolation (pulling network and power) of win-3450 to preserve volatile evidence and halt any background exfiltration processes.
•	Full Memory Forensics: Perform a live acquisition of the host's memory to capture the active PowerShell process, scripts, and any credentials.
•	Expand Investigation Scope: Review all logons and connections to FILESRV-01 in the last 24 hours to identify any other compromised accounts or systems.
•	Search for Staged Data: Scan the host win-3450 for the C:\Users\michael.ascot\downloads\exfiltration\ folder 
•	Network Forensic Analysis: Scrutinize all outbound connections from the subnet containing win-3450 around the alert timeframe for signs of data exfiltration.
Note: This cleanup step is a critical marker in the attack lifecycle. The attacker has likely completed their objective on this host. The focus must now shift to containing data loss by analyzing network logs for exfiltration, and preserving volatile evidence from the compromised host before the attacker's next move, which is likely to be establishing persistence elsewhere or executing the final exfiltration of the staged data.

### Alerts #1025-1034 - Active Data Exfiltration Phase
•	Alert Received: "Suspicious Parent Child Relationship" on compromised host win-3450 for user michael.ascot,
•	Activity: Multiple alerts (9 instances) show nslookup.exe processes being spawned by the same malicious PowerShell instance (PID 3728) from within the exfiltration directory.

Key Observations:
2.	Technique Identification: The attacker is using DNS exfiltration/tunneling to bypass network security controls. This involves encoding stolen data into DNS query subdomains directed at an attacker-controlled DNS server (haz4rdw4re.io).
3.	Data Encoding Pattern: The command-line arguments show base64-like encoded strings being appended to the malicious domain:
o	UEsDBBQAAAAIANigLlfVU3cDIgAAAI.haz4rdw4re.io
o	8AAAAbAAAAQ2xpZW50UG9ydGZvbGlv.haz4rdw4re.io (includes "ClientPortfolio" in base64)
o	U3VtbWFyeS54bHN4c87JTM0rCcgvKk.haz4rdw4re.io (includes "Summary.xlsx" in base64)
4.	Attack Progression: This confirms the successful completion of the attack chain:
o	Initial access (phishing) → Credential theft → Lateral movement → Data collection → Data staging → Active exfiltration
5.	Time stamp of all of these exfiltration alerts were at the same timestamp 01/01/2026 22:45:23
6.	The exfiltration is occurring from the same compromised user (michael.ascot)
Conclusion: Critical True Positive - Data Exfiltration in Progress
The attacker is actively exfiltrating stolen financial data using DNS as a covert channel. This maps to:
•	T1048.003: Exfiltration Over Alternative Protocol - Exfiltration Over Unencrypted Non-C2 Protocol
•	T1071.004: Application Layer Protocol - DNS
•	T1560.001: Archive Collected Data - Archive via Utility (data appears to be archived/encoded)
Actions taken:
•	Escalation: Elevated incident severity to Critical and initiated full incident response protocol.
•	IOC Documentation: Recorded critical IOCs and 5Ws (who, what, where, when, and why) such as timestamps, hostname, command line, compromised user account, and MITRE ATT&CK correlation. 
Recommended Actions:
•	DNS Blocking: Added haz4rdw4re.io and all subdomains to DNS blackhole/sinkhole.
•	Full Network Isolation: Complete network disconnection of win-3450 (pull from network if necessary).
•	DNS Log Analysis: Initiated emergency analysis of all DNS queries from the entire network to identify other compromised systems.
•	Incident Declaration: Formally declare a Critical Security Incident and activated full incident response team.
•	Network-Wide DNS Monitoring: Implement immediate DNS query logging and analysis across all systems to identify other potential exfiltration attempts.
•	Data Breach Assessment: Begin formal data breach assessment process for financial records exposure.
•	Regulatory Notification: Initiate communication with legal/compliance for potential regulatory reporting requirements (SOX, GDPR, etc.).
•	Forensic Preservation: Secure all logs, memory dumps, and disk images from both win-3450 and FILESRV-01 as evidence.
•	Attack Reconstruction: Use captured DNS queries to reconstruct exfiltrated data by decoding the base64 fragments.
Note: This represents a successful data breach. The attacker has bypassed traditional security controls using DNS tunneling.

Conclusion: The organization was compromised via a phishing email, leading to a multi-stage attack where the attacker stole credentials, moved laterally to a file server containing financial records, staged the data locally, and exfiltrated it using DNS tunneling. The incident demonstrates a complete intrusion lifecycle, from initial access to data theft.
## Overall Takeaways

This investigation highlighted essential principles of effective SOC analysis and incident response:
•	Context separates noise from threats: The majority of alerts were false positives—benign Windows processes or spam. Accurate triage required correlating events with system knowledge (normal svchost.exe behavior) and business context (marketing emails sent to a hat company).
•	Correlation reveals the attack chain: Isolated alerts became significant only when linked by the compromised user and host. Connecting activity across email, endpoint, and network logs was crucial to reconstructing the kill chain: phishing → execution → discovery → lateral movement → collection → exfiltration.
•	Understanding attacker tradecraft enables prediction: Mapping events to the MITRE ATT&CK framework (e.g., PowerView.ps1 for discovery, robocopy for staging, DNS for exfiltration) provided a model of adversary behavior, turning individual alerts into a predictable narrative and guiding response.
•	Impact dictates response priority: The investigation correctly escalated when activity shifted to high-value assets (SSF-FinancialRecords). Translating technical events into business risk—prioritizing the theft of financial data over initial compromise—ensures the response focuses on mitigating real damage.

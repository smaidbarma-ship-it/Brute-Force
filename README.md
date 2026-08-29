# Brute-Force
Simulated and investigated a Brute force attack on Splunk.

## Objective
The objective of this project was to simulate a brute-force attack against a target system and use Splunk to detect, analyze, and investigate the malicious authentication attempts. This project demonstrates hands-on experience with SIEM log analysis, identifying attack patterns, and understanding security events.

## Technologies & Tools Used
*   *SIEM:* Splunk Enterprise
*   *Environment:* Virtual Machines (Host-Only Network Setup) ; Windows 11 (Target), Ubuntu 22.4 (Splunk), Kali Linux (Attacker).
*   *Attack Simulation Tool:* Hydra(on Kali's msf Console).
*   *Log Sources:* Windows Security Event Logs (Event ID 4625 for failed logins) / Linux SSH Logs and 4624 for successful logins.

## Step-by-Step Walkthrough

### Step 1: Simulating the Attack
I initiated a high-volume automated brute-force attack targeting a specific user account to generate authentication failures, which was done via Metasploit SMB modules within secure and private host-only networks.

### Step 2: Configuring Splunk Ingestion
Set up Splunk to ingest the security logs from the targeted machine's Splunk Universal Forwarder to ensure all event data was properly captured for analysis.

### Step 3: Detecting the Brute-Force Pattern
Using Splunk Search Processing Language (SPL), I isolated the spikes in failed login attempts. I filtered by specific event signatures to map out the attacker's timeline and source IP address.

## Investigation Findings & SPL Analysis
During the investigation, the following key indicators of compromise (IoCs) were identified:
*   *Targeted Account:* Test User.
*   *Total Failed Attempts:* 103 events in 2 minutes.
*   *Source IP Address:* 192.168.232.130

*Splunk Search Query Used:*
index=* EventCode=4625 
| rex "Source Network Address:\s+(?<SrcIP>\S+)"
| rex field=_raw max_match=0 "Account Name:\s+(?<User_List>\S+)"
| rex field=_raw max_match=0 "Logon Type:\s+(?<Type_List>\d+)"
| eval User=mvindex(User_List, -1)
| eval Type=mvindex(Type_List, -1)
| stats count by SrcIP, User, Type

## Key Takeaways & Mitigation
*   *Detection:* Automated brute-force attacks leave a distinct footprint in Splunk characterized by rapid, high-volume authentication failures from a single source.
*   *Defensive Recommendations:* Implementing strict account lockout policies, deploying Multi-Factor Authentication (MFA), and setting up automated alerting thresholds in Splunk to flag anomalous login velocities.

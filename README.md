<div align="center">

# 📊 SIEM Threat Detection & Log Analysis with Splunk

### Detecting Security Incidents Through Log Correlation, SPL Queries, and Real-Time Dashboards

[![Splunk](https://img.shields.io/badge/Splunk_Enterprise_10.2-000000?style=for-the-badge&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu_24.04-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![SPL](https://img.shields.io/badge/SPL-Search_Processing_Language-4EAA25?style=for-the-badge&logo=gnu-bash&logoColor=white)](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

<br>

*A hands-on cybersecurity project demonstrating SIEM operations — from Splunk installation and log ingestion to writing SPL detection queries, building security dashboards, creating alert rules, and investigating a real multi-stage web attack scenario across correlated log sources.*

<br>

[Setup & Ingestion](#part-1---splunk-setup--log-ingestion) · [SPL Fundamentals](#part-2---spl-search-fundamentals) · [Threat Detection](#part-3---threat-detection-queries) · [Dashboards](#part-4---security-monitoring-dashboards) · [Alerts](#part-5---alert-rules--automated-detection) · [Investigation](#part-6---attack-investigation--incident-timeline)

</div>

---

## 📋 Project Overview

A SIEM (Security Information and Event Management) platform is the nerve center of a Security Operations Center. It collects logs from across the environment, correlates events, and enables analysts to detect and investigate threats. This project demonstrates practical SIEM skills using Splunk — the industry-leading platform — working with **33.4 million real security events** from the Boss of the SOC dataset to detect web attacks, privilege changes, and reconstruct an attacker's full activity timeline.

### What This Project Covers

| Section | Skill Demonstrated | Tools Used |
|---|---|---|
| **Setup & Ingestion** | Splunk installation, data inputs, index management | Splunk Enterprise, `inputs.conf` |
| **SPL Fundamentals** | Search Processing Language queries and data exploration | SPL, `stats`, `table`, `timechart` |
| **Threat Detection** | Writing detection queries for real attack patterns | SPL, `where`, `eval`, `search` |
| **Dashboards** | Building operational security monitoring dashboards | Splunk Classic Dashboards |
| **Alert Rules** | Creating automated detection with alert actions | Scheduled searches, triggers |
| **Investigation** | Correlating events to reconstruct an attack timeline | Cross-sourcetype correlation, `timechart` |

---

## 🏗️ Lab Environment

The lab runs Splunk Enterprise on Ubuntu 24.04 inside VirtualBox, analyzing over 33 million security events across 26 different log sources from the Boss of the SOC (BOTS) v1 dataset.

### Architecture

```
+----------------------------------------------------------------+
|                      Splunk SIEM Lab                           |
|                                                                |
|   +----------------------+       +-------------------------+   |
|   |   BOTS v1 Dataset    |       |   Splunk Enterprise     |   |
|   |   (33.4M events)     |       |   (Ubuntu 24.04 VM)     |   |
|   |                      |       |                         |   |
|   |  - Windows Security  | ----> |   Index: botsv1         |   |
|   |  - Fortinet Firewall | ----> |                         |   |
|   |  - Suricata IDS      | ----> |   Source Types: 26      |   |
|   |  - Stream HTTP/TCP   | ----> |                         |   |
|   |  - Sysmon            | ----> |   Time Range: Aug 2016  |   |
|   |  - Stream DNS        | ----> |                         |   |
|   +----------------------+       +-------------------------+   |
+----------------------------------------------------------------+
```

### Log Sources (Top 10 by Event Count)

| Source Type | Event Count | Purpose |
|---|---|---|
| **WinEventLog:Security** | 14,131,490 | Windows authentication, process creation, privilege events |
| **fgt_traffic** | 7,675,023 | Fortinet firewall traffic logs |
| **suricata** | 5,078,376 | IDS/IPS alerts and network detections |
| **stream:tcp** | 1,754,601 | TCP connection metadata |
| **stream:ip** | 1,435,025 | IP-layer packet metadata |
| **stream:dns** | 1,369,998 | DNS query/response records |
| **XmlWinEventLog:Microsoft-Windows-Sysmon/Operational** | 559,792 | Detailed process/network Sysmon telemetry |
| **stream:smb** | 448,008 | SMB file-sharing activity |
| **fgt_utm** | 257,477 | Fortinet UTM security events |
| **stream:http** | 39,010 | HTTP request/response stream data |

> **Data source:** This project uses the [Boss of the SOC (BOTS) v1](https://github.com/splunk/botsv1) dataset — a realistic, labeled attack dataset created by Splunk for security training. It contains a complete web attack scenario targeting a corporate environment, with data captured from August 2016.

---

## Part 1 - Splunk Setup & Log Ingestion

### Installing Splunk Enterprise on Ubuntu

I install Splunk Enterprise on an Ubuntu 24.04 VM:

```bash
# Download the .deb package from splunk.com (requires free account)
sudo dpkg -i splunk.deb

# Start Splunk for the first time and accept the license
sudo /opt/splunk/bin/splunk start --accept-license --answer-yes --run-as-root
```

During the initial start, Splunk prompts for an admin username and password. After starting, the web interface is available at `http://localhost:8000`.

<div align="center">
<img src="assets/01-splunk-home.png" alt="Splunk Enterprise home screen" width="700">
<br><em>Splunk Enterprise 10.2.2 home screen showing available apps, bookmarks, and common tasks — the starting point for all SIEM operations</em>
</div>

<br>

### Verifying the botsv1 Index

I install the BOTS v1 dataset as a Splunk app by extracting it into `/opt/splunk/etc/apps/`, then restart Splunk to load the index. After restart, I verify the index is loaded and contains data:

```spl
| eventcount summarize=false index=botsv1 | table index, count
```

<div align="center">
<img src="assets/02-indexes.png" alt="botsv1 index containing 33.4 million events" width="700">
<br><em>The botsv1 index loaded with 33,413,777 events — successful data ingestion confirmed</em>
</div>

<br>

### Verifying Data Ingestion Across Source Types

I explore the variety of log sources in the dataset:

```spl
index=botsv1 | stats count by sourcetype | sort -count
```

<div align="center">
<img src="assets/03-data-ingestion.png" alt="Event count broken down by sourcetype" width="700">
<br><em>26 distinct source types ingested — from Windows Security events (14.1M) and Fortinet firewall logs (7.6M) to Suricata IDS alerts (5M) and stream data across multiple protocols</em>
</div>

<br>

---

## Part 2 - SPL Search Fundamentals

### Exploring Windows Security Event Codes

Before hunting for threats, I explore the distribution of Windows Security event codes to understand what activity the dataset captured:

```spl
index=botsv1 sourcetype="WinEventLog:Security"
| stats count by EventCode
| sort -count
| head 20
```

<div align="center">
<img src="assets/04-event-exploration.png" alt="Windows event code distribution showing top EventCodes" width="700">
<br><em>Top Windows EventCodes — 4703 (token rights adjusted), 4689 (process exited), 4688 (process created), and 4624 (successful logon) dominate the dataset, providing rich telemetry for behavioral detections</em>
</div>

<br>

**Key EventCodes identified in the dataset:**

| EventCode | Description | Count | Detection Use |
|---|---|---|---|
| **4703** | Token rights adjusted | 3,034,865 | Privilege manipulation |
| **4689** | Process has exited | 2,577,818 | Process execution tracking |
| **4688** | New process created | 2,575,010 | Execution-based threat hunting |
| **4624** | Account successfully logged on | 407,843 | Authentication monitoring |
| **4634** | Account logged off | 407,595 | Session tracking |
| **4672** | Special privileges assigned | 378,789 | Privilege escalation detection |
| **4656** | Object handle requested | 306,618 | File/registry access monitoring |

### Key SPL Commands Used

| Command | Purpose | Example |
|---|---|---|
| `stats` | Aggregate data | `stats count by src_ip` |
| `table` | Display specific fields | `table _time, user, src_ip` |
| `timechart` | Time-based aggregation | `timechart span=1h count` |
| `where` | Filter with expressions | `where count > 100` |
| `eval` | Create calculated fields | `eval source_type=sourcetype` |
| `search` | Filter with search terms | `search uri_path="*passwd*"` |
| `sort` | Order results | `sort -count` |
| `head` | Limit results | `head 10` |

---

## Part 3 - Threat Detection Queries

### Process Execution Anomaly Detection

Process creation events (EventCode 4688) provide one of the richest sources for threat hunting. I search for the most frequently executed processes to establish a baseline and identify outliers:

```spl
index=botsv1 sourcetype="WinEventLog:Security" EventCode=4688
| stats count AS executions by New_Process_Name
| where executions > 100
| sort -executions
| head 20
```

<div align="center">
<img src="assets/05-brute-force.png" alt="Process execution frequency analysis" width="700">
<br><em>Process execution baseline — Splunk Universal Forwarder components dominate (expected), while spikes in wmiprvse.exe (45,429), dllhost.exe (9,866), and conhost.exe (9,313) warrant investigation as these are commonly abused by attackers for lateral movement and command execution</em>
</div>

<br>

> **Why this matters:** In real threat hunting, attackers often use legitimate Windows binaries ("living-off-the-land") to evade detection. Establishing execution baselines lets analysts spot anomalous spikes that indicate attacker activity — for example, unusually high PowerShell, WMI, or cmd.exe execution rates.

### Web Application Attack Detection

I search the HTTP stream data for common web attack patterns — path traversal, local file inclusion, and remote command execution attempts:

```spl
index=botsv1 sourcetype="stream:http"
| search uri_path="*SELECT*" OR uri_path="*UNION*" OR uri_path="*../*" OR uri_path="*passwd*"
| stats count by src_ip, uri_path
| sort -count
```

<div align="center">
<img src="assets/06-web-attacks.png" alt="Web attack detection revealing a single attacker with multiple attack techniques" width="700">
<br><em>Web attack detection revealing a single attacker (40.80.148.42) attempting path traversal, local file inclusion (/etc/passwd, /.htpasswd), and Windows command execution via cgi-bin — using UTF-8 overlong encoding bypass techniques (%C0%AF, %E0%80%AF) to evade web application filters</em>
</div>

<br>

**Attack techniques identified from a single source IP (40.80.148.42):**

| Attack Category | Example Payload | Technique |
|---|---|---|
| **Local File Inclusion** | `/etc/passwd`, `/etc/passwd%00` | Null-byte injection for path bypass |
| **Credential File Access** | `/.htpasswd`, `/.passwd` | Sensitive file enumeration |
| **Remote Command Execution** | `/cgi-bin/../../winnt/system32/cmd.exe` | Classic IIS directory traversal |
| **Encoding Bypass** | `%C0%AF`, `%E0%80%AF` | UTF-8 overlong encoding |
| **Application Targeting** | `/vti_bin/`, `/samples/`, `/scripts/` | Known-vulnerable path probing |

This single scan identified **40.80.148.42** as the primary attacker — an IP that becomes the focus of the Part 6 investigation.

---

## Part 4 - Security Monitoring Dashboards

### Building the SOC Overview Dashboard

I build a four-panel security monitoring dashboard that gives an analyst immediate visibility into key security indicators:

<div align="center">
<img src="assets/07-soc-dashboard.png" alt="SOC Security Overview dashboard with four panels" width="700">
<br><em>SOC Security Overview dashboard showing process creation trends, top web attackers (with 40.80.148.42 dominating at ~17K requests), most-executed processes, and top accounts by activity — combining multiple data sources into a single analyst view</em>
</div>

<br>

**Dashboard panels:**

**Panel 1 — Process Creations Over Time (Line Chart):**

```spl
index=botsv1 sourcetype="WinEventLog:Security" EventCode=4688
| timechart span=1h count AS "Process Creations"
```

**Panel 2 — Top Source IPs Hitting Web Server (Bar Chart):**

```spl
index=botsv1 sourcetype="stream:http"
| stats count by src_ip
| sort -count
| head 10
```

**Panel 3 — Top Processes Executed (Bar Chart):**

```spl
index=botsv1 sourcetype="WinEventLog:Security" EventCode=4688
| stats count by New_Process_Name
| sort -count
| head 15
```

**Panel 4 — Top Accounts by Activity (Bar Chart):**

```spl
index=botsv1 sourcetype="WinEventLog:Security" EventCode=4688
| stats count by Account_Name
| sort -count
| head 10
```

### Geolocation Panel

I add a geographic analysis panel showing the countries and cities of web requests hitting the server:

```spl
index=botsv1 sourcetype="stream:http"
| iplocation src_ip
| where isnotnull(Country)
| stats count by Country, City
| sort -count
| head 20
```

<div align="center">
<img src="assets/08-geo-dashboard.png" alt="Geolocation table showing top attack source cities" width="700">
<br><em>Geolocation analysis revealing Washington, D.C. as the top source of web traffic (17,547 requests) — traced to the attacker IP 40.80.148.42 — followed by Ashburn, Oakland, and other U.S. cities</em>
</div>

<br>

> **Why dashboards matter:** In a real SOC, analysts monitor dashboards continuously during their shifts. A well-designed dashboard surfaces anomalies immediately — the dominance of a single IP in the "Top Source IPs" panel (40.80.148.42 at ~17K requests vs ~1,500 for the next highest) is the kind of pattern that jumps out visually and triggers investigation.

---

## Part 5 - Alert Rules & Automated Detection

### Creating a Web Attack Alert

I configure an automated alert to detect path traversal and local file inclusion attempts in real time:

<div align="center">
<img src="assets/09-alert-config.png" alt="Splunk alert configuration for web attack detection" width="700">
<br><em>Automated web attack alert configuration — detects path traversal, LFI, and command execution attempts via SPL pattern matching, scheduled to run every hour</em>
</div>

<br>

**Alert configuration:**

- **Title:** Web Attack Detected - Path Traversal or LFI
- **Search:**
  ```spl
  index=botsv1 sourcetype="stream:http"
  | search uri_path="*passwd*" OR uri_path="*../*" OR uri_path="*cmd.exe*" OR uri_path="*%C0%AF*"
  | stats count by src_ip
  | where count > 5
  ```
- **Schedule:** Every hour
- **Trigger:** Number of results > 0
- **Severity:** High

### Alert Rule Library

<div align="center">
<img src="assets/10-triggered-alerts.png" alt="Splunk alert list showing three configured security alerts" width="700">
<br><em>Configured security alerts providing layered automated detection — web attacks (High), suspicious process execution (Medium), and new account creation (High) — all scheduled and enabled</em>
</div>

<br>

| Alert Name | Condition | Severity | Schedule |
|---|---|---|---|
| **Web Attack Detected - Path Traversal or LFI** | >5 malicious URI patterns from single IP | High | Every hour |
| **Suspicious Process Execution** | Unusual cmd.exe/powershell.exe by same account >10 times | Medium | Every hour |
| **New Account Created** | EventCode 4720 detected | High | Every hour |

---

## Part 6 - Attack Investigation & Incident Timeline

### Investigating the Attacker's Full Activity

Using the attacker IP identified in Part 3 (**40.80.148.42**), I correlate their activity across all log sources to reconstruct the full attack timeline:

```spl
index=botsv1 (src_ip="40.80.148.42" OR src="40.80.148.42")
| eval source_type=sourcetype
| timechart span=5m count by source_type
```

<div align="center">
<img src="assets/11-attack-timeline.png" alt="Correlated attack timeline across multiple log sources" width="700">
<br><em>Cross-source correlation of attacker 40.80.148.42 — revealing 35,732 total events spanning HTTP stream data, IP/TCP connections, and Suricata IDS alerts, all clustered into a 45-minute attack window starting at 21:35 on August 10, 2016</em>
</div>

<br>

### Reconstructed Attack Timeline

Correlating events across `stream:http`, `stream:ip`, `stream:tcp`, and `suricata` reveals the attacker's activity pattern:

| Time (UTC) | Phase | Primary Evidence | Activity |
|---|---|---|---|
| **21:35** | Reconnaissance | stream:http (2,512 events) + suricata (3,003 alerts) | Initial web scanning — IDS immediately detects attack patterns |
| **21:40** | Active Exploitation | stream:http (1,713) + suricata (2,880) | Path traversal + LFI payloads sent |
| **21:45** | Exploitation | stream:http (729) + suricata (1,653) | Attack continues, exploring attack surface |
| **21:50** | Peak Activity | stream:http (2,340) + suricata (4,237 alerts) | Attack intensifies — highest IDS alert volume |
| **21:55** | Exploitation | stream:http (2,207) + suricata (3,797) | Continued aggressive scanning |
| **22:00-22:10** | Persistence Attempts | stream:http (~1,500-1,800/5min) | TCP/IP layer activity stops, only HTTP continues |
| **22:15-22:20** | Winding Down | stream:http (~947-1,594) | Attack activity decreases |

**Key investigative findings:**

1. **Clear attack signature:** The attacker generated 10,000+ Suricata IDS alerts in under 15 minutes — an overwhelming volume that any SOC would catch
2. **Multi-layer detection:** The same malicious activity appears across HTTP stream, TCP/IP stream, and IDS logs simultaneously — demonstrating defense-in-depth
3. **Attack duration:** The entire attack spanned approximately 45 minutes, typical for automated scanning tools
4. **Attack scope:** 35,732 total events from a single source IP — high signal-to-noise ratio for detection
5. **Attacker technique signature:** Heavy use of UTF-8 overlong encoding (`%C0%AF`, `%E0%80%AF`) suggests an automated scanner or custom tooling rather than manual exploitation

> **Why this matters:** In a real incident response, the ability to correlate events across multiple log sources and reconstruct an attack timeline is one of the most valuable skills an analyst can have. This investigation demonstrates the complete workflow: identify the attacker via anomaly detection (Part 3), correlate their activity across all available log sources, establish the timeline, and document the scope of the incident. From initial detection to full timeline reconstruction took under 10 SPL queries.

---

## 🔑 Key SPL Queries Reference

A quick reference of all detection queries used throughout this project:

| Query Purpose | Key SPL |
|---|---|
| Event count by index | `\| eventcount summarize=false index=botsv1 \| table index, count` |
| Sourcetype distribution | `index=botsv1 \| stats count by sourcetype \| sort -count` |
| EventCode frequency | `index=botsv1 sourcetype="WinEventLog:Security" \| stats count by EventCode \| sort -count` |
| Process execution baseline | `index=botsv1 EventCode=4688 \| stats count by New_Process_Name \| sort -count` |
| Web attack detection | `index=botsv1 sourcetype="stream:http" \| search uri_path="*../*" OR uri_path="*passwd*"` |
| Top web source IPs | `index=botsv1 sourcetype="stream:http" \| stats count by src_ip \| sort -count` |
| Geolocation analysis | `index=botsv1 sourcetype="stream:http" \| iplocation src_ip \| stats count by Country, City` |
| Cross-source IP correlation | `index=botsv1 (src_ip="X" OR src="X") \| eval source_type=sourcetype \| timechart span=5m count by source_type` |

---

## 🧰 Tools & Environment

| Component | Version | Purpose |
|---|---|---|
| **Ubuntu** | 24.04 LTS | Host operating system (VirtualBox VM) |
| **Splunk Enterprise** | 10.2.2 | SIEM platform |
| **BOTS v1 Dataset** | 1.0 | Realistic attack scenario data (33.4M events) |
| **VirtualBox** | Latest | VM hypervisor |

---

## 📚 Summary

This project demonstrates practical SIEM operations skills through six progressive exercises:

1. **Setup & Ingestion** — Installed Splunk Enterprise 10.2.2 on Ubuntu 24.04, loaded the BOTS v1 dataset (33.4 million events across 26 source types), and verified successful ingestion
2. **SPL Fundamentals** — Explored data structure using SPL queries, identifying key Windows EventCodes (4688, 4703, 4624) and understanding the dataset's composition
3. **Threat Detection** — Wrote detection queries for process execution anomalies and web application attacks, identifying a single attacker IP (40.80.148.42) performing path traversal, LFI, and RCE attempts with encoding bypass techniques
4. **Security Dashboards** — Built a four-panel SOC Overview dashboard plus geolocation analysis, visualizing the attacker's activity against normal baseline traffic
5. **Alert Rules** — Configured three automated alerts (web attacks, suspicious process execution, new account creation) with severity-based triage and hourly scheduling
6. **Attack Investigation** — Correlated 35,732 events from the attacker across HTTP stream, TCP/IP stream, and Suricata IDS logs, reconstructing a 45-minute attack timeline with 10,000+ IDS alerts demonstrating defense-in-depth detection

### Skills Demonstrated

`SIEM Operations` · `Splunk Administration` · `SPL Queries` · `Threat Detection` · `Log Analysis` · `Security Dashboards` · `Alert Engineering` · `Incident Investigation` · `Log Correlation` · `Attack Timeline Reconstruction`

---

<div align="center">

### 🔗 Related Projects

[![Wireshark](https://img.shields.io/badge/Wireshark_Threat_Detection-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)](https://github.com/jesse12-21/wireshark-threat-detection)
[![Nmap](https://img.shields.io/badge/Nmap_Network_Scanning-005571?style=for-the-badge&logo=gnu-bash)](https://github.com/jesse12-21/nmap-network-recon)
[![Suricata](https://img.shields.io/badge/Suricata_IDS_Rules-EF3B2D?style=for-the-badge&logo=argo)](https://github.com/)

<br>

*Built as a cybersecurity portfolio project — feedback and suggestions welcome.*

</div>

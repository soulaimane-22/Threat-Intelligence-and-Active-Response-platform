# Threat Intelligence and Active Response

An end-to-end security monitoring, threat intelligence enrichment, risk assessment, and automated response platform built with Wazuh, n8n, MISP, VirusTotal, PostgreSQL, Suricata, Docker, and MITRE ATT&CK.

The project demonstrates how endpoint and network detections can be transformed into enriched, prioritized incidents and followed by automated containment actions such as file quarantine, malicious process termination, and source IP blocking.

# Threat Intelligence and Active Response

Automated threat detection, intelligence enrichment, risk assessment, and active response platform built with Wazuh, MISP, VirusTotal, n8n, PostgreSQL, and Suricata.

![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-005571?style=flat-square&logo=wazuh&logoColor=white)
![n8n](https://img.shields.io/badge/n8n-Automation-EA4B71?style=flat-square&logo=n8n&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![MISP](https://img.shields.io/badge/MISP-Threat%20Intelligence-2C3E50?style=flat-square)
![VirusTotal](https://img.shields.io/badge/VirusTotal-Threat%20Intelligence-394EFF?style=flat-square&logo=virustotal&logoColor=white)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-E34F26?style=flat-square)
![Suricata](https://img.shields.io/badge/Suricata-Network%20Detection-EF3B2D?style=flat-square)
![Docker](https://img.shields.io/badge/Docker-Containerization-2496ED?style=flat-square&logo=docker&logoColor=white)
![VirtualBox](https://img.shields.io/badge/VirtualBox-Virtualization-183A61?style=flat-square&logo=virtualbox&logoColor=white)
![Python](https://img.shields.io/badge/Python-Active%20Response-3776AB?style=flat-square&logo=python&logoColor=white)
![Telegram](https://img.shields.io/badge/Telegram-Notifications-26A5E4?style=flat-square&logo=telegram&logoColor=white)


## Table of Contents

- [Project Overview](#project-overview)
- [Key Capabilities](#key-capabilities)
- [Architecture](#architecture)
- [Lab Infrastructure](#lab-infrastructure)
- [Core Components](#core-components)
- [Detection and Response Pipeline](#detection-and-response-pipeline)
- [Threat Intelligence Workflow](#threat-intelligence-workflow)
- [Detection Scenarios](#detection-scenarios)
- [Automated Response Controls](#automated-response-controls)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Security Dashboard](#security-dashboard)
- [Repository Structure](#repository-structure)
- [Configuration Reference](#configuration-reference)
- [Deployment and Reproduction](#deployment-and-reproduction)
- [Testing](#testing)
- [Security and Secret Management](#security-and-secret-management)
- [Limitations and Future Work](#limitations-and-future-work)
- [Project Outcome](#project-outcome)

## Project Overview

The objective of this project is to reduce the amount of manual work required between security detection and incident response.

Wazuh collects and correlates endpoint security events. Suricata provides network visibility on the Linux endpoint. n8n receives selected Wazuh alerts and orchestrates enrichment, risk evaluation, persistence, notification, and response. PostgreSQL is used both as an IOC cache and as an incident/action history store. MISP and VirusTotal provide external threat intelligence context when an IOC is not already known locally.

The implementation focuses on five practical detection scenarios:

| Scenario | Detection | Enrichment / Analysis | Automated Outcome |
| --- | --- | --- | --- |
| Malware / suspicious file | Wazuh FIM on Windows | PostgreSQL cache, MISP, VirusTotal, risk evaluation | File quarantine |
| SSH brute force | Wazuh authentication correlation | Rule context, MITRE ATT&CK, risk evaluation | Source IP blocking |
| Malicious process | Custom process monitoring + Wazuh rule | PostgreSQL cache, MISP, VirusTotal, risk evaluation | Process termination and incident report |
| Known IOC | PostgreSQL cache hit | Reuses previous intelligence | Skips unnecessary external lookups |
| Network scan | Suricata + Wazuh | MITRE ATT&CK correlation, deduplication | Incident registration and notification |

## Key Capabilities

- Windows and Linux endpoint monitoring with Wazuh agents.
- File Integrity Monitoring for suspicious file creation.
- SSH brute-force detection and automated IP blocking.
- Custom Linux process monitoring with PID, executable path, command line, user, and SHA-256 extraction.
- Network scan detection through Suricata and Wazuh.
- IOC enrichment through MISP and VirusTotal.
- PostgreSQL IOC caching to reduce repeated external API lookups.
- Dynamic incident risk scoring and criticality classification.
- MITRE ATT&CK correlation for supported detections.
- Automated file quarantine, process termination, and firewall response.
- Telegram notifications and response confirmation.
- PostgreSQL tracking of incidents and automated actions.
- Event deduplication for network scan processing.
- Custom Wazuh dashboard for detection and response visibility.

## Architecture

### Network Infrastructure

The lab separates endpoint simulation from the containerized security platform.

![Network Topology](docs/architectures/Network%20Topology.png)

The monitored and attacking virtual machines communicate over a VirtualBox host-only network. The Fedora Docker host is reached through the host/LAN path, while the containerized services communicate internally through a dedicated Docker bridge network.

### Threat Detection and Automated Response Architecture

![Threat Detection and Automated Response Architecture](docs/architectures/Threat%20Intelligence%20and%20Active%20Response.png)

The main event path is:

```text
Windows / Ubuntu / Suricata
            |
            v
       Wazuh Manager
        /         \
       v           v
Wazuh Indexer      n8n
       |            |
       v            +--> PostgreSQL cache / incident history
Wazuh Dashboard     +--> MISP
                    +--> VirusTotal
                    +--> Telegram
                    +--> Wazuh REST API
                              |
                              v
                    Automated endpoint response
```

Wazuh Manager forwards selected alerts to the n8n webhook. n8n uses the Wazuh REST API on TCP 55000 when an automated response must be triggered. Authentication is performed through the Wazuh API and the returned JWT is used as a Bearer token for subsequent requests.

## Lab Infrastructure

| System / Network | Role | Address / Range |
| --- | --- | --- |
| Fedora host | Docker host for the security platform | - |
| UbuntuEndpoint | Linux endpoint, SSH target, process monitoring, Suricata sensor | `192.168.56.102` |
| WindowsServer | Windows endpoint used for file monitoring and quarantine | `192.168.56.107` |
| Kali Linux | Controlled attack simulation | `192.168.56.108` |
| VirtualBox host-only network | VM-to-VM lab network | `192.168.56.0/24` |
| Docker bridge | Internal container communication | `172.19.0.0/16` |
| Docker gateway | Bridge gateway | `172.19.0.1` |

VirtualBox runs on the Windows host. Fedora is not attached directly to the VirtualBox host-only network. Access from the virtual machines to services published by Docker is therefore routed through the VM NAT / host LAN path to the Fedora Docker host.

## Core Components

| Component | Purpose | Main Port(s) |
| --- | --- | --- |
| Wazuh Manager `4.14.7` | Event analysis, correlation, integrations, response coordination | `1514/tcp`, `1515/tcp`, `55000/tcp`, `514/udp` |
| Wazuh Indexer | Security event indexing and storage | `9200/tcp` |
| Wazuh Dashboard | Detection investigation and visualization | `443/tcp` |
| n8n | Enrichment, decision logic, notifications, response orchestration | `5678/tcp` |
| PostgreSQL | IOC cache, incidents, action history, event deduplication | `5432/tcp` |
| MISP | Threat intelligence lookup | `8443/tcp` |
| VirusTotal API | External file hash reputation | HTTPS |
| Suricata | Network intrusion detection on UbuntuEndpoint | AF_PACKET on `enp0s8` |
| Telegram Bot API | Security notifications and incident reports | HTTPS |

MISP also relies on supporting services such as MariaDB, Redis/Valkey, MISP modules, and an Nginx frontend inside the Docker environment.

## Detection and Response Pipeline

```text
1. Endpoint or network activity generates a security event
2. Wazuh collects and evaluates the event
3. Selected alerts are forwarded to the n8n webhook
4. n8n identifies the applicable detection scenario
5. IOC and event context are extracted
6. PostgreSQL is checked for previously analyzed intelligence
7. MISP and VirusTotal are queried when required
8. A risk score and criticality are calculated
9. The incident is stored in PostgreSQL
10. Telegram notification is generated
11. High-risk events can trigger Wazuh Active Response
12. Response state is tracked as pending, sent, and completed
13. Confirmation events are correlated back to the original action
```

This design keeps detection, intelligence enrichment, decision logic, persistence, notification, and containment as separate stages while still allowing them to operate as one automated pipeline.

## Threat Intelligence Workflow

For hash-based detections, PostgreSQL acts as the first intelligence layer.

```text
Incoming SHA-256
      |
      v
PostgreSQL IOC cache
   /          \
 HIT          MISS
  |             |
  |             v
  |            MISP
  |          /      \
  |       FOUND    NOT FOUND
  |         |          |
  |         |          v
  |         |     VirusTotal
  |         |          |
  +---------+----------+
            |
            v
      Normalize result
            |
            v
       Cache / update IOC
            |
            v
       Risk assessment
```

A known IOC can therefore be processed without repeating MISP and VirusTotal requests. This reduces external API usage and provides faster response for previously analyzed indicators.

The public n8n workflow does not contain live credentials. MISP, VirusTotal, PostgreSQL, Wazuh API, and Telegram credentials must be recreated locally after importing the workflow.

## Detection Scenarios

### Scenario 1: Malware Detection and File Quarantine

The Windows endpoint monitors:

```text
C:\malware
```

Wazuh File Integrity Monitoring detects file creation and computes the SHA-256 hash. Rule `554` is used for file-add events, while rule `553` is later used as confirmation that the file disappeared from the monitored directory after quarantine.

The enrichment path is:

```text
FIM detection
    |
    v
SHA-256 extraction
    |
    v
PostgreSQL cache
    |
    +--> MISP
    |
    +--> VirusTotal
    |
    v
Risk evaluation
    |
    v
Incident + action registration
    |
    v
Wazuh REST API
    |
    v
!quarantine-file.exe
```

The custom quarantine implementation accepts the Wazuh Active Response JSON message through standard input, extracts the target path, validates that the target is located under `C:\malware`, creates `C:\Wazuh-Quarantine` when required, and moves the file using a timestamp and random identifier in the destination filename.

A path restriction prevents the response mechanism from moving arbitrary files outside the monitored directory.

The action lifecycle is persisted in PostgreSQL:

```text
pending -> sent -> completed
```

Completion is correlated with the later Wazuh file deletion event.

### Scenario 2: SSH Brute-Force Detection and IP Blocking

Kali Linux generates repeated SSH authentication attempts against UbuntuEndpoint. Wazuh correlates the failures with rule `5712` and MITRE ATT&CK technique `T1110 - Brute Force`.

n8n extracts the attacker address, endpoint information, rule context, and MITRE data before calculating the incident risk score.

When the response threshold is reached, n8n authenticates against the Wazuh API and triggers the firewall Active Response on the Ubuntu agent.

```text
Hydra attack
    |
    v
Ubuntu authentication logs
    |
    v
Wazuh rule 5712
    |
    v
Risk evaluation
    |
    v
Register block action
    |
    v
Wazuh Active Response
    |
    v
firewall-drop
    |
    v
Attacker IP blocked
```

Wazuh rule `651` is used to identify the response confirmation. n8n matches the confirmation against the pending PostgreSQL action and marks it as completed.

### Scenario 3: Malicious Process Detection and Termination

UbuntuEndpoint runs the custom monitor:

```text
/usr/local/bin/wazuh-process-monitor-s3.sh
```

The script looks for `ncat` / `nc` processes operating in listening mode and emits structured information containing:

```text
PID
user
executable
SHA-256
command line
```

Wazuh parses the generated event with the custom `scenario3-process-fields` decoder and raises custom rule `100211`.

n8n performs IOC cache lookup, MISP / VirusTotal enrichment when necessary, result normalization, risk calculation, incident registration, Telegram notification, and generation of a Markdown incident report.

For high-risk detections, n8n triggers:

```text
!kill-process-s3.py
```

The response script does not terminate a process using the PID alone. It validates:

```text
PID format and protected PID range
expected executable path
expected SHA-256 format
actual /proc/<pid>/exe target
SHA-256 of the running executable
```

Only after the validation succeeds does it send `SIGTERM`. If the process is still running after the grace period, `SIGKILL` is used as a fallback.

Successful execution writes a `KILL_PROCESS_SUCCESS` event to the Wazuh Active Response log. Custom rule `100212` detects the confirmation and n8n marks the corresponding PostgreSQL action as completed.

### Scenario 4: Known IOC Cache

This scenario validates the local intelligence cache.

When the received hash already exists in `ioc_cache`, the workflow immediately reuses the stored source, verdict, and reputation score.

```text
Wazuh alert
    |
    v
PostgreSQL IOC cache
    |
   HIT
    |
    v
Reuse intelligence
    |
    v
Risk / response pipeline
```

MISP and VirusTotal are not queried for that event.

### Scenario 5: Nmap Network Scan Detection

Suricata monitors the Ubuntu host-only interface:

```text
enp0s8
```

The project-specific rule detects TCP SYN scanning behavior:

```text
SID: 1000050
Threshold: 20 SYN packets / 60 seconds / source
Classification: network-scan
```

Suricata writes JSON events to:

```text
/var/log/suricata/eve.json
```

The Wazuh agent collects this file and custom rule `100220` correlates the detection with MITRE ATT&CK technique:

```text
T1046 - Network Service Discovery
```

Before creating a new incident, n8n inserts the Wazuh event ID into `processed_wazuh_events`. The PostgreSQL primary key prevents the same event from being processed multiple times.

A new scan generates a high-priority incident record and a Telegram notification.

## Automated Response Controls

The project adds validation and state tracking around automated containment rather than executing actions blindly.

| Response | Target | Control |
| --- | --- | --- |
| File quarantine | Windows file | Target must resolve under `C:\malware` |
| Process termination | Linux process | PID, executable path, and SHA-256 must all match |
| IP blocking | Source IP | Triggered from correlated SSH brute-force context |
| Action confirmation | All supported responses | PostgreSQL matches the confirmation event with a recent pending/sent action |

The custom process response attempts graceful termination first and uses forced termination only if the process remains alive.

## MITRE ATT&CK Coverage

The project uses MITRE ATT&CK information as part of detection context and incident prioritization.

| Detection | Technique |
| --- | --- |
| SSH brute force | `T1110 - Brute Force` |
| Network scan | `T1046 - Network Service Discovery` |

Additional detections can be mapped to MITRE ATT&CK as the detection library grows.

## Security Dashboard

The Wazuh dashboard provides a consolidated view of detections, MITRE ATT&CK coverage, alert severity, and automated response activity.

![Security Dashboard](docs/dashboard/Screenshot%20From%202026-10-05%2022-22-22.png)

The dashboard includes views for detection timelines, detections by scenario, MITRE ATT&CK tactics and techniques, alert severity distribution, automated containment actions, and top detection rules.

## Repository Structure

```text
.
├── README.md
├── configs
│   ├── docker
│   │   ├── docker-compose.yml
│   │   └── .env.example
│   ├── n8n
│   │   └── workflow
│   │       └── Wazuh_Threat_Intelligence_Pipeline.json
│   ├── postgresql
│   │   └── schema.sql
│   ├── suricata
│   │   ├── scenario5.rules
│   │   └── suricata-project-settings.yaml
│   └── wazuh
│       ├── manager
│       │   ├── custom-manager-config.xml
│       │   ├── local_rules.xml
│       │   ├── scenario3_kill_decoder.xml
│       │   └── scenario3_process_decoder.xml
│       ├── ubuntu-agent
│       │   └── custom-agent-config.xml
│       └── windows-agent
│           └── windows-agent.conf
├── docs
│   ├── architectures
│   │   ├── Network Topology.png
│   │   └── workflow.png
│   └── dashboard
│       └── dashboard-wazuh.png
└── scripts
    ├── active-response
    │   ├── kill-process-s3.py
    │   └── quarantine-file.py
    └── monitoring
        └── wazuh-process-monitor-s3.sh
```

Private documentation, original exports, credentials, runtime data, certificates, and local backups are intentionally excluded from this structure.

## Configuration Reference

| File | Purpose |
| --- | --- |
| `configs/docker/docker-compose.yml` | Sanitized container stack definition |
| `configs/docker/.env.example` | Required environment variable placeholders |
| `configs/wazuh/manager/local_rules.xml` | Custom Wazuh detection and confirmation rules |
| `configs/wazuh/manager/scenario3_process_decoder.xml` | Scenario 3 process event decoder |
| `configs/wazuh/manager/scenario3_kill_decoder.xml` | Active Response confirmation decoder |
| `configs/wazuh/manager/custom-manager-config.xml` | Project-specific Wazuh Manager integration snippets |
| `configs/wazuh/ubuntu-agent/custom-agent-config.xml` | SSH, process, response-log, and Suricata collection |
| `configs/wazuh/windows-agent/windows-agent.conf` | Windows FIM and response-log collection |
| `configs/suricata/scenario5.rules` | Nmap TCP SYN scan detection |
| `configs/suricata/suricata-project-settings.yaml` | Relevant Suricata network and capture settings |
| `configs/n8n/workflow/Wazuh_Threat_Intelligence_Pipeline.json` | Sanitized automation workflow |
| `configs/postgresql/schema.sql` | Database schema without incident or IOC data |
| `scripts/monitoring/wazuh-process-monitor-s3.sh` | Suspicious listening-process discovery |
| `scripts/active-response/kill-process-s3.py` | Validated Linux process termination |
| `scripts/active-response/quarantine-file.py` | Restricted Windows file quarantine |

## Deployment and Reproduction

### 1. Clone the repository

```bash
git clone https://github.com/soulaimane-22/Threat-Intelligence-and-Active-Response-platform.git
cd Threat-Intelligence-and-Active-Response-platform
```

### 2. Prepare environment variables

Create a local environment file from the provided example:

```bash
cp configs/docker/.env.example .env
```

Replace every placeholder with your own values.

The real `.env` must remain local and must never be committed.

### 3. Prepare certificates and private material

Private keys and certificates from the lab are intentionally not included.

Generate or provide the TLS material required by your deployment and update the Docker volume paths when necessary.

### 4. Deploy the containerized services

Review the sanitized Compose file and adapt paths, credentials, and published ports to the target environment.

```bash
docker compose -f configs/docker/docker-compose.yml up -d
```

Confirm the deployment:

```bash
docker compose -f configs/docker/docker-compose.yml ps
```

### 5. Initialize PostgreSQL

Apply the schema:

```bash
psql \
  -h <POSTGRES_HOST> \
  -U <POSTGRES_USER> \
  -d <POSTGRES_DB> \
  -f configs/postgresql/schema.sql
```

The project schema contains:

```text
ioc_cache
incidents
actions_taken
processed_wazuh_events
```

### 6. Configure Wazuh Manager

Deploy the custom rules and decoders from:

```text
configs/wazuh/manager/
```

Merge the required project-specific integration and log collection snippets from `custom-manager-config.xml` into the Wazuh Manager configuration.

Do not blindly replace an existing `ossec.conf`; merge only the required project blocks and validate the configuration before restarting the manager.

### 7. Configure UbuntuEndpoint

Install and enroll the Wazuh agent, then add the project-specific collection blocks from:

```text
configs/wazuh/ubuntu-agent/custom-agent-config.xml
```

Install the process monitor:

```bash
sudo install -m 750 \
  scripts/monitoring/wazuh-process-monitor-s3.sh \
  /usr/local/bin/wazuh-process-monitor-s3.sh
```

Install the process response script on the Wazuh agent:

```bash
sudo install -m 750 \
  scripts/active-response/kill-process-s3.py \
  /var/ossec/active-response/bin/kill-process-s3.py
```

Install Suricata, adapt `HOME_NET` and the capture interface to your lab, deploy `scenario5.rules`, and ensure `eve.json` is readable by the Wazuh agent.

### 8. Configure WindowsServer

Enroll the Windows Wazuh agent and apply the project-specific FIM configuration from:

```text
configs/wazuh/windows-agent/windows-agent.conf
```

Create the monitored directory:

```text
C:\malware
```

Deploy the quarantine implementation under the Wazuh Active Response directory. The current Manager / n8n workflow expects the executable name:

```text
quarantine-file.exe
```

The repository contains the Python source rather than a compiled binary. Build or package the executable locally for the target Windows environment.

### 9. Import the n8n workflow

Import:

```text
configs/n8n/workflow/Wazuh_Threat_Intelligence_Pipeline.json
```

The public workflow is intentionally sanitized and disabled by default.

Recreate and assign credentials for:

```text
PostgreSQL
MISP HTTP header authentication
VirusTotal API
Wazuh API authentication
Telegram Bot API
```

Review all endpoint URLs and credential bindings before activation.

### 10. Configure Wazuh to n8n forwarding

The Wazuh Manager forwards selected alerts to the n8n webhook:

```text
http://n8n:5678/webhook/wazuh_alert
```

In a different deployment, replace the service name and port with the correct reachable n8n endpoint.

### 11. Validate the complete pipeline

Verify:

```text
Wazuh agent connectivity
Wazuh custom rule loading
Suricata event generation
n8n webhook reception
PostgreSQL inserts
MISP / VirusTotal lookups
Telegram delivery
Wazuh REST API authentication
Active Response execution
Response confirmation
```

## Testing

All attack simulations must be performed only inside an authorized lab.

Example validation activities used by the project include:

```bash
# Scenario 2: generate controlled SSH authentication failures
hydra -l <TEST_USER> -P <TEST_PASSWORD_LIST> ssh://<UBUNTU_ENDPOINT>

# Scenario 3: start a controlled listening process
nohup ncat --listen --keep-open 8000 >/tmp/scenario3-ncat.log 2>&1 </dev/null &

# Scenario 5: controlled network discovery
nmap -sS <UBUNTU_ENDPOINT>
```

Scenario 1 can be tested with a harmless controlled file placed under `C:\malware`. The workflow should receive the FIM alert and follow the configured enrichment and quarantine path.

No real malicious samples are included in this repository.

## Security and Secret Management

The repository is designed to keep sensitive runtime material local.

The `.gitignore` excludes environment files, local secret directories, credentials, private keys, certificates, database dumps, runtime logs, backups, and private project documentation.

The public n8n workflow has been sanitized to remove credential references, webhook identifiers, instance metadata, and the real Telegram chat ID.

Never commit:

```text
MISP API keys
VirusTotal API keys
Telegram bot tokens
Telegram chat identifiers
Wazuh API credentials
JWT tokens
PostgreSQL passwords
private TLS keys
agent enrollment secrets
database contents
malware samples
```

For a production environment, use a dedicated secret-management solution and trusted TLS certificates instead of lab-oriented local credentials or self-signed certificate exceptions.

## Limitations and Future Work

The current repository represents the implemented portfolio version of the lab.

Terraform was part of the initial infrastructure requirements but is intentionally not implemented in the current version. Deployment is currently based on Docker Compose plus documented endpoint configuration.

Possible future improvements include:

- Terraform-based infrastructure provisioning.
- Centralized secret management.
- Automated certificate provisioning and rotation.
- Broader MITRE ATT&CK technique coverage.
- Additional endpoint and network detection scenarios.
- Automated integration tests for custom Wazuh rules and response scripts.
- CI checks for secret leakage and configuration validation.
- More granular risk scoring based on asset criticality and intelligence confidence.
- Additional incident reporting formats and retention policies.
- Production-grade high availability and backup procedures.

## Project Outcome

The final lab demonstrates a complete security workflow from detection to containment:

```text
Detect
  |
  v
Extract context / IOC
  |
  v
Check local intelligence
  |
  v
Enrich when necessary
  |
  v
Correlate and score risk
  |
  v
Persist incident
  |
  v
Notify
  |
  v
Execute response
  |
  v
Confirm response
```

The result is a practical implementation showing how Wazuh can be extended beyond event collection by combining threat intelligence, workflow orchestration, persistence, network detection, and validated automated response.

---


### Author

**Soulaimane**  
Security & Big Data Student  
Focused on Cybersecurity, Threat Intelligence, Security Monitoring, and Big Data

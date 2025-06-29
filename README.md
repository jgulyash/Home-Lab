# 🔐 Cybersecurity Home Lab Projects - Jay Gulyash

Welcome to my **Cybersecurity Home Lab Projects** repository—a living documentation of my hands-on journey into offensive and defensive cybersecurity. This lab is designed to emulate real-world environments where I develop, refine, and enhance my capabilities across the cybersecurity spectrum, including **SOC operations, threat hunting, penetration testing, malware analysis, cloud security, and dark web intelligence**.

The goal of this lab is to simulate modern threat landscapes while practicing both **attack and defense methodologies**. Each project is aligned with industry-standard frameworks like the **MITRE ATT&CK** and includes end-to-end workflows—from adversary emulation to detection engineering and incident response.

This repository not only tracks technical implementations but also serves as a blueprint for:
- Building and tuning SIEM and IDS/IPS/XDR systems.
- Investigating endpoint and network threats.
- Executing penetration tests safely in a controlled environment.
- Conducting malware analysis and developing custom detections.
- Exploring cloud misconfigurations and AWS-specific attack vectors.
- Gathering intelligence from dark web forums while maintaining OPSEC.
- Leveraging **LLM and machine learning models** for automated detection and security analysis.

All activities occur within a fully isolated, self-contained, and legally compliant lab built on a robust foundation of macOS virtualization, Linux-based services, Windows environments, and AWS cloud infrastructure. This lab not only supports my continuous learning but also reflects how security operations are evolving with the integration of AI and cloud-native technologies.

---

## 💽 Home Lab Setup

| Component        | Description                                           |
|------------------|-------------------------------------------------------|
| **Primary Host** | MacBook Pro M4 Max (Virtualization Host)             |
| **Server**       | Synology NAS DS1522+ (File, Web, DHCP, DNS)          |
| **Client Device**| MacBook Air M2                                        |
| **Virtual Machines** | - Windows Client (Testing) <br> - Ubuntu (Testing/Development) <br> - Kali Linux (Penetration Testing) <br> - Windows Server 2008 (Metasploitable3 - Vulnerability Analysis) <br> - OPNsense + Zenarmor (NextGen Firewall) <br> - Wazuh (SIEM & XDR) |

---

## 🎯 Goals

- ✅ Simulate SOC operations, incident response, and detection engineering.
- ✅ Perform endpoint threat hunting across Windows, Linux, and MacOS.
- ✅ Conduct penetration testing and post-exploitation analysis.
- ✅ Analyze malware and develop detection rules aligned to MITRE ATT&CK.
- ✅ Explore AWS cloud security, misconfigurations, and detection.
- ✅ Conduct dark web intelligence collection and analysis.
- ✅ Build and experiment with LLM/ML-assisted threat detection.

---

## 🚀 Projects

### 🔥 SOC Operations Simulation

**Objective:** Build a SOC environment with Wazuh SIEM, IDS/IPS (Snort/Suricata), and OPNsense firewall for detection engineering.

**Steps:**
1. Deploy Wazuh server and agents (Windows, Linux, MacOS).
2. Configure OPNsense + Zenarmor for IDS/IPS.
3. Simulate attacks (Nmap, brute force, phishing) via Kali.
4. Correlate firewall and endpoint logs in Wazuh.
5. Create dashboards and alerts.
6. Document detection processes and improvements.

---

### 🎯 Endpoint Threat Hunting & Forensics

**Objective:** Detect adversary behavior, persistence, and evasion techniques on multiple OS endpoints.

**Steps:**
1. Install Sysmon (Windows) and AuditD (Linux).
2. Simulate malware infections and lateral movement.
3. Analyze logs for:
   - Process creation anomalies
   - Unauthorized remote connections
   - Persistence mechanisms
4. Develop hunting hypotheses.
5. Document findings and detections.

---

### 🕵️ Penetration Testing Lab

**Objective:** Perform vulnerability discovery and exploitation against Metasploitable3.

**Steps:**
1. Scan with Nmap.
2. Identify exploitable services.
3. Use Metasploit and manual techniques to exploit vulnerabilities.
4. Conduct post-exploitation (privilege escalation, pivoting).
5. Write a penetration test report.
6. Map findings to MITRE ATT&CK.

---

### 🧐 Malware Analysis & Detection Engineering

**Objective:** Analyze malware samples to craft detection rules.

**Steps:**
1. Isolate Windows VM (snapshot + no internet).
2. Obtain samples (TheZoo, MalwareBazaar - safely and legally).
3. Perform dynamic analysis (process, network, registry behavior).
4. Conduct static analysis (PEStudio, Strings, etc.).
5. Develop Wazuh detection rules.
6. Document analysis and ATT&CK mapping.

---

### ☁️ AWS Cloud Security & Incident Response

**Objective:** Understand and detect AWS cloud security threats.

**Steps:**
1. Deploy AWS EC2 and S3 instances.
2. Introduce common misconfigurations (open S3, open SSH).
3. Simulate attacks from Kali.
4. Enable AWS GuardDuty, CloudTrail, and AWS Config.
5. Investigate and remediate incidents.
6. Write a cloud incident response playbook.

---

### 🔍 Dark Web Threat Intelligence

**Objective:** Develop threat intelligence collection and analysis skills.

**Steps:**
1. Deploy a secure Ubuntu VM for Tor browsing.
2. Use Tor Browser and Ahmia to navigate .onion sites.
3. Collect intelligence (TTPs, IOCs) from forums and marketplaces.
4. Map findings to MITRE ATT&CK or adversary profiles.
5. Produce an intelligence report.

---

### 🤖 LLM/ML-Assisted Threat Detection

**Objective:** Automate threat detection using machine learning and LLMs.

**Steps:**
1. Install Jupyter Notebook on Ubuntu VM.
2. Export and parse Wazuh or firewall logs.
3. Perform anomaly detection using Python (`pandas`, `scikit-learn`).
4. Leverage OpenAI API to summarize logs or detect anomalies.
5. Build simple triage automation or detection models.
6. Document workflow and outcomes.

---

## 📺 Execution Roadmap

| Priority | Project                               | Status     |
|----------|----------------------------------------|------------|
| 🥇       | SOC Operations Simulation              | 🔲 Planned |
| 🥈       | Endpoint Threat Hunting & Forensics    | 🔲 Planned |
| 🥉       | Penetration Testing Lab                | 🔲 Planned |
| 🏅       | Malware Analysis & Detection Engineering| 🔲 Planned |
| 🏅       | AWS Cloud Security                     | 🔲 Planned |
| 🏅       | Dark Web Threat Intelligence           | 🔲 Planned |
| 🏅       | LLM/ML-Assisted Threat Detection       | 🔲 Planned |

---

## 📚 References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [OPNsense + Zenarmor](https://www.zenarmor.com/)
- [AWS Cloud Security](https://aws.amazon.com/security/)
- [TheZoo Malware Repository](https://github.com/ytisf/theZoo)
- [MalwareBazaar](https://bazaar.abuse.ch/)

---

## 📜 License

This repository is for educational purposes only. All activities are conducted within isolated and legally authorized lab environments. No actions are taken against unauthorized systems or networks.

---

## 👾 Contact

**Jay Gulyash**  
[LinkedIn](#) | [Website](https://furywrenlabs.io) | gulyash@yahoo.com

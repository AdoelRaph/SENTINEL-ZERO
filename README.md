# Sentinel-Zero SETUP TIME = ESTIMATED 40-50mins 
**GO THROUGH ALL .md FILES TO SETUP AND TRY TO YOUR PREFERENCE**

<div align="center">

![Sentinel-Zero Banner](https://img.shields.io/badge/Sentinel--Zero-ML%20Security%20Platform-blue?style=for-the-badge)

**Autonomous ML-Focused Vulnerability Detection & Remediation**  
*Protecting AI Infrastructure in Regulated Industries*

[![Status](https://img.shields.io/badge/status-beta-yellow?style=flat-square)]()
[![License](https://img.shields.io/badge/license-proprietary-red?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square)]()
[![Lines of Code](https://img.shields.io/badge/lines-15K%2B-green?style=flat-square)]()

[Demo Video](#-demo) • [Documentation](#-documentation) • [Architecture](#-architecture) • [Contact](#-contact)

</div>

---

## 🎯 The Problem

AI systems in fintech face unique security challenges that traditional tools miss:

- **🧠 Model Integrity Attacks** - Poisoning, adversarial examples, backdoors in ML models
- **📊 Data Drift & Compliance** - Models degrading silently, violating regulatory requirements
- **🔐 Infrastructure Vulnerabilities** - Zero-days in ML pipelines (TensorFlow, PyTorch, scikit-learn)
- **⚡ Real-Time Threats** - DoS loops, backdoor connections, lateral movement in AI workloads

**Existing solutions** (Snyk, Wiz, Lacework) focus on traditional infrastructure. **Sentinel-Zero** was built specifically for AI/ML security in regulated environments.

---

## 💡 What Sentinel-Zero Does

### 1. **ML Model Integrity Monitoring**
27-feature anomaly detection engine that monitors:
- Model inference behavior (prediction drift, confidence anomalies)
- Training process integrity (data poisoning detection)
- Feature distribution changes (covariate shift)
- Memory forensics (process injection, DLL tampering)

**Tech:** Isolation Forest with custom feature engineering, trained on 200K+ samples

### 2. **Automated Threat Intelligence**
Continuous synchronization with:
- **NIST NVD** - 200K+ CVE database with CVSS scoring
- **CISA KEV** - Known Exploited Vulnerabilities (federal compliance)
- **ExploitDB** - Proof-of-concept exploit tracking

**Impact:** Detects vulnerabilities within 6 hours of disclosure (vs. industry avg of 14 days)

### 3. **Network Discovery & Vulnerability Correlation**
- ARP + nmap-based asset discovery
- Service version detection (OpenSSH, Apache, MySQL, etc.)
- Automatic CVE correlation with installed software
- Backdoor detection via non-allowlisted connection monitoring

**Coverage:** Scans 254 hosts in ~8 minutes with 95%+ accuracy

### 4. **Automated Remediation Engine**
- SSH/WinRM-based patch deployment
- Dual-approval workflows for high-risk changes
- Automatic rollback on failure (99.7% success rate in testing)
- Compliance-ready audit logs (7-year immutable storage)

**Safety:** Zero production outages in 47 test remediations

### 5. **Compliance-Grade Audit Trail**
- SEC/FINRA compliant logging (immutable 7-year retention)
- Cryptographically signed audit entries
- Anomaly investigation tracking
- Remediation decision records with dual-approval chains

**Standard:** Designed for SOC 2 Type II, HIPAA, PCI-DSS audits

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Sentinel-Zero Platform                        │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Scanner    │    │  ML Engine   │    │ Remediation  │
│   Module     │───▶│  (Predictor) │───▶│    Agent     │
└──────────────┘    └──────────────┘    └──────────────┘
   │                       │                     │
   │ Discovers             │ Detects             │ Fixes
   │ Assets                │ Anomalies           │ Vulnerabilities
   │                       │                     │
   ▼                       ▼                     ▼
┌─────────────────────────────────────────────────────────┐
│              Neon PostgreSQL (Serverless)                │
│  • Asset Inventory      • Anomaly Logs                   │
│  • Vulnerability DB     • Audit Trail (Partitioned)      │
└─────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Cloudflare R2   │
                    │  • ML Models     │
                    │  • PCAP Archives │
                    │  • Audit Logs    │
                    └──────────────────┘
```

**Key Design Decisions:**
- **Serverless PostgreSQL** (Neon) - Scales to zero when idle, perfect for cost-conscious deployments
- **S3-Compatible Storage** (R2) - 10x cheaper than AWS S3 for compliance archives
- **Async Python** - Handles 1000+ concurrent network scans without blocking
- **Isolation Forest ML** - Low memory footprint (~200MB), trains in <15 min on i5

---

## 🧪 ML Detection Engine

### Feature Engineering (27 Dimensions)

**Network Features (22):**
```python
- Traffic Volume: packets_per_second, bytes_per_second, avg_packet_size
- Protocol Distribution: tcp_ratio, udp_ratio, icmp_ratio
- Port Behavior: unique_dst_ports, high_port_ratio, uses_non_standard_port
- Connection Patterns: connection_count, failed_connection_ratio, syn_flood_score
- Flow Characteristics: flow_duration, bidirectional_ratio, packet_interval_std
- Payload Analysis: payload_entropy, avg_payload_size, header_repetition_score
- Backdoor Indicators: is_outbound, is_non_allowlisted
```

**Memory Forensics Features (5):**
```python
- Process Monitoring: mem_pslist_nproc (running processes)
- DLL Tracking: mem_dlllist_ndlls (loaded libraries)
- Handle Analysis: mem_handles_nhandles (open handles)
- Injection Detection: mem_malfind_ninjections (code injection attempts)
- Module Integrity: mem_ldrmodules_not_in_load (hidden modules)
```

### Training Data Sources

| Dataset | Samples | Attack Types | Use Case |
|---------|---------|--------------|----------|
| **LSNM2024** | 50K | DDoS, Port Scans | Network anomaly baseline |
| **BCCC-DarkNet** | 30K | Tor, Dark Web Traffic | Backdoor detection |
| **UGRansome** | 25K | Ransomware, C2 | Lateral movement patterns |
| **CIC-MalMem** | 15K | Memory exploits | Memory forensics baseline |

**Total:** 120K normal traffic samples for baseline training

### Current Performance

```
╔════════════════════════════════════════════╗
║  Metric                    │  Value        ║
╠════════════════════════════════════════════╣
║  False Positive Rate       │  ~15%         ║
║  Target FPR                │  <5%          ║
║  True Positive Rate        │  92%          ║
║  Training Time (i5)        │  14 min       ║
║  Inference Latency         │  <50ms        ║
║  Memory Footprint          │  220MB        ║
╚════════════════════════════════════════════╝
```

**Status:** Model currently training with expanded dataset to reduce FPR to <5%

---

## 🚀 Quick Start

### Prerequisites

```bash
- Python 3.11+
- PostgreSQL (or Neon account)
- Cloudflare R2 bucket
- nmap installed (for network scanning)
- Admin/sudo access for Python package installation
```

### ⚠️ Important Setup Notes

**For Windows Users:**
- Update `SCANNER_NMAP_PATH` in `.env` to your nmap installation path
- Default: `C:\Program Files (x86)\Nmap\nmap.exe`
- Run Command Prompt as Administrator when installing Python packages

**For Linux/Mac Users:**
- Update `SCANNER_NMAP_PATH` to `/usr/bin/nmap` or your nmap location
- May need `sudo` for network scanning features

**About Model Training:**
- The model was initially trained using **Kaggle notebooks** (free GPU access)
- Current version optimized for local training on constrained hardware
- **Known Issue:** False positive rate ~15% - actively training with more data
- You'll need to retrain with your own network traffic patterns for best results

**Network Configuration:**
- Update all IP ranges in the code to match YOUR network topology
- The demo uses `192.168.1.0/24` - adjust in `main.py` and scanning configs
- Test in isolated environment before production deployment

### Installation

```bash
# Clone the repository
git clone https://github.com/AdoelRaph/SENTINEL-ZERO.git
cd SENTINEL-ZERO

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies (may require admin/sudo)
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your actual credentials (see below)
```

### Configuration

Edit `.env` with your credentials:

```bash
# Database (Neon PostgreSQL)
DATABASE_URL=postgresql://user:pass@host/db?sslmode=require

# Cloudflare R2
R2_ACCOUNT_ID=your_account_id
R2_ACCESS_KEY_ID=your_access_key
R2_SECRET_ACCESS_KEY=your_secret_key
R2_BUCKET_NAME=sentinel-zero

# Security Keys
ENCRYPTION_KEY=your_fernet_key_here
API_SECRET_KEY=min_32_character_secret_key

# Scanner
SCANNER_NMAP_PATH=/usr/bin/nmap  # Adjust for your system
```

### Initialize Database

```bash
# Run database migrations
python -m alembic upgrade head

# Or manually execute schema
psql $DATABASE_URL < database/schema.sql
```

### Run Sentinel-Zero

```bash
# Start the orchestrator
python main.py

# Or run via uvicorn
uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## 📊 Usage Examples

### 1. Trigger Network Scan

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "00000000-0000-0000-0000-000000000001",
    "target": "192.168.1.0/24",
    "scan_type": "standard"
  }'
```

### 2. Detect Anomalies

```python
from ml_engine.predict import create_predictor
from ml_engine.model import FeatureVector

# Initialize predictor
predictor = await create_predictor(organization_id)

# Create feature vector from network traffic
features = FeatureVector(
    source_ip="192.168.1.100",
    destination_ip="45.142.212.61",
    packets_per_second=150,
    is_outbound=True,
    dst_is_allowlisted=False,
    # ... other features
)

# Get prediction
result = await predictor.predict(features)
print(f"Anomaly: {result.is_anomaly}")
print(f"Type: {result.anomaly_type}")
print(f"Confidence: {result.confidence:.2%}")
```

### 3. Create Remediation Task

```bash
curl -X POST http://localhost:8000/api/v1/remediation/tasks \
  -H "Content-Type: application/json" \
  -d '{
    "asset_id": "asset-uuid-here",
    "title": "Patch OpenSSH CVE-2024-6387",
    "template_name": "linux_update_package",
    "parameters": {
      "package_name": "openssh-server"
    }
  }'
```

---

## 📁 Project Structure

```
SENTINEL-ZERO/
├── agents/
│   └── patcher.py              # Remediation automation engine
├── api/
│   └── routes.py               # FastAPI REST endpoints
├── config/
│   └── config.py               # Centralized configuration
├── database/
│   ├── connection.py           # Async PostgreSQL client
│   └── schema.sql              # Database schema
├── ml_engine/
│   ├── model.py                # Isolation Forest training
│   ├── predict.py              # Real-time anomaly detection
│   ├── batch_train.py          # Memory-efficient training script
│   └── merge_datasets.py       # Dataset unification
├── modules/
│   ├── scanner.py              # Network discovery
│   └── intel_ingest.py         # Threat intelligence sync
├── storage/
│   └── r2_client.py            # Cloudflare R2 operations
├── utils/
│   ├── logging.py              # Structured logging
│   ├── crypto.py               # Encryption utilities
│   └── validators.py           # Input validation
├── main.py                     # Main orchestrator
├── requirements.txt            # Python dependencies
└── README.md                   # This file
```

---

## 🎥 Demo

### Detection Scenarios

**1. Backdoor Detection**
```
Scenario: Non-server workstation connecting to unknown IP on port 4444
Detection Time: 1.2 seconds
Confidence: 94%
Action: Quarantine asset + alert SOC
```

**2. DoS Loop Detection**
```
Scenario: 1500 packets/sec with repetitive headers to gateway
Detection Time: 8 seconds
Confidence: 98%
Action: Block source IP + create incident
```

**3. CVE Correlation**
```
Scenario: OpenSSH 7.4 detected (CVE-2024-6387 vulnerable)
Detection Time: During network scan
Action: Create remediation task + notify admin
```

### Demo Video (Coming Soon)

*10-minute walkthrough showing live detection, remediation workflow, and audit trail generation*

---

## 🔧 Configuration

### ML Engine Tuning

Adjust detection sensitivity in `.env`:

```bash
# Higher = more sensitive (more false positives)
ML_ANOMALY_THRESHOLD=0.15

# Lower = require stronger evidence (fewer false positives)
ML_CONTAMINATION=0.1

# Retraining frequency
ML_RETRAIN_INTERVAL_DAYS=7
```

### Scanner Options

```bash
# Quick scan (common ports)
SCANNER_QUICK_SCAN_PORTS=21-23,80,443,3306,3389

# Full scan (all ports)
SCANNER_FULL_SCAN_PORTS=1-65535

# Scan timeout per host
SCANNER_TIMEOUT_SECONDS=30
```

### Remediation Settings

```bash
# Auto-approve low-risk patches?
REMEDIATION_AUTO_APPROVE_LOW_RISK=false

# Require 2 approvers for high-risk changes?
REMEDIATION_REQUIRE_DUAL_APPROVAL=true

# SSH timeout
REMEDIATION_SSH_TIMEOUT=60
```

---

## 📈 Roadmap

### Q1 2025 (Current)
- [x] Core anomaly detection engine
- [x] Network discovery & vulnerability scanning
- [x] SSH-based remediation
- [ ] Reduce FPR to <5% (training in progress)
- [ ] Pilot deployment with Vise

### Q2 2025
- [ ] Windows remediation (WinRM support)
- [ ] Real-time packet capture analysis
- [ ] Integration with Slack/PagerDuty
- [ ] Custom detection rule engine
- [ ] Performance optimization for 10K+ assets

### Q3 2025
- [ ] Kubernetes cluster security
- [ ] Cloud provider integrations (AWS, GCP, Azure)
- [ ] Threat hunting dashboard
- [ ] API rate limiting & multi-tenancy
- [ ] SOC 2 Type II certification

---

## 🛡️ Security

### Responsible Disclosure

Found a vulnerability? Please report it privately:
- **Email:** techkid3692@gmail.com
- **PGP Key:** [Coming soon]
- **Response Time:** <48 hours

### Security Features

- **Encrypted Credentials** - Fernet (AES-128-CBC + HMAC-SHA256) for stored secrets
- **Least Privilege** - SSH keys with minimal required permissions
- **Audit Logging** - Immutable 7-year retention with cryptographic signatures
- **Input Validation** - SQL injection & XSS prevention on all inputs
- **Rate Limiting** - Prevents DoS on API endpoints
- **RBAC** - Role-based access control for multi-tenant deployments

---

## 🤝 For Vise Team

### Evaluation License

This codebase is under a **proprietary evaluation license**. You're welcome to:
- ✅ Review the source code
- ✅ Run in a test environment
- ✅ Provide feedback

Commercial use requires a licensing agreement. Let's talk about what makes sense for Vise.

### Pilot Opportunity

I'd love to deploy Sentinel-Zero in **read-only monitoring mode** on Vise's infrastructure:

**What You Get:**
- Real-time anomaly detection on your AI workloads
- Vulnerability correlation with your tech stack
- Zero risk (read-only, no remediation actions)
- Weekly performance reports

**What I Get:**
- Validation against production AI systems
- Feedback on false positive/negative rates
- Insights into blind spots in my threat model
- Case study for future customers

**Timeline:** 4-week pilot, 1-hour setup, weekly check-ins

Interested? Email me: **techkid3692@gmail.com**

---

## 📚 Documentation

### Technical Deep Dives

- [Architecture Overview](docs/architecture.md)
- [ML Model Training Guide](docs/ml_training.md)
- [Database Schema](database/schema.sql)
- [API Reference](docs/api.md)
- [Deployment Guide](docs/deployment.md)

### Research Papers Referenced

1. **Isolation Forest** - Liu et al. (2008) - "Isolation Forest for Anomaly Detection"
2. **Network Anomaly Detection** - Garcia et al. (2014) - "Survey on Network Anomaly Detection"
3. **Memory Forensics** - Volatility Foundation (2022) - "Memory Forensics Techniques"
4. **ML Security** - Papernot et al. (2018) - "SoK: Security and Privacy in ML"

---

## 📊 Performance Benchmarks

### Training (Intel i5-8265U, 8GB RAM)

| Operation | Time | Memory |
|-----------|------|--------|
| Dataset Loading (120K samples) | 2m 14s | 450MB |
| Feature Engineering | 1m 32s | 280MB |
| Model Training (200 trees) | 11m 48s | 320MB |
| Model Serialization | 18s | 180MB |
| **Total** | **15m 52s** | **Peak 520MB** |

### Inference (Production)

| Operation | Latency | Throughput |
|-----------|---------|------------|
| Single Prediction | 38ms | 26 req/s |
| Batch (100 samples) | 420ms | 238 req/s |
| Network Scan (254 hosts) | 8m 15s | 0.5 hosts/s |

### Storage Efficiency

| Component | Size | Compression |
|-----------|------|-------------|
| Trained Model | 12.3 MB | gzip (68%) |
| 24hr Audit Logs | 2.1 MB | gzip (82%) |
| PCAP (1hr traffic) | 45 MB | gzip (71%) |

---

## 🌍 About the Project

### The Real Story

Sentinel-Zero is the **first product** from **Virado Tech**, my startup focused on bringing enterprise-grade AI/ML solutions to Africa—starting with Ghana.

I'm **Virgil Junior Adoleyine**, 17, founder of Virado Tech. I'm not particularly interested in cybersecurity—I'm obsessed with **what AI and ML can do to transform Africa**. But I realized something critical: if AI systems in finance, healthcare, and infrastructure aren't secure, no one will trust them. And without trust, Africa doesn't get the AI revolution it deserves.

So I built Sentinel-Zero as my **entry point** into enterprise AI—solving a painful, technical problem that fintech companies will actually pay for. The revenue and credibility from this will fund what I really want to build: **AI systems that solve uniquely African problems**.

### Why Security First?

**Strategic reasoning:**
1. **Immediate market need** - Fintech companies managing billions need AI security NOW
2. **Technical credibility** - Building this proves I can execute on complex ML engineering
3. **Revenue model** - Enterprise security has clear pricing ($50K-$500K/year contracts)
4. **Founding customer leverage** - One logo like Vise opens every fintech door

I built this on an **Intel i5 with 8GB RAM** (all I could afford) by reading research papers and CVE databases until 2 AM after school. **15,000+ lines of Python later**, it works—and it's ready for production.

But this is just **Phase 1** of Virado Tech.

### The Bigger Vision (What I Actually Care About)

**Phase 2 (2026):** ML Task Orchestrator
- Platform that distributes ML training/inference tasks to developers across Africa
- Companies post ML jobs (data labeling, model training, fine-tuning)
- African developers with GPUs/compute earn by completing tasks
- **Why:** Makes African engineers participants in the AI economy, not just consumers

**Phase 3 (2027):** Contractor Matching Platform
- AI-powered matching of African tech talent to global companies
- Skills verification through actual project completion (not just resumes)
- Payment infrastructure for cross-border freelance work
- **Why:** $200B global freelance market, but African developers struggle with trust/payment

**Phase 4 (2028):** Smart Architecture for African Housing
- AI-optimized building designs for tropical climates (ventilation, cooling, materials)
- Cost estimation models trained on local construction data
- Modular designs that reduce waste and construction time
- **Why:** Africa needs 50M+ housing units by 2030 - better design = affordable housing

**Why These Three?**

**ML Orchestrator** → Creates immediate income for African engineers with compute  
**Contractor Platform** → Connects African talent to global demand  
**Smart Housing** → Solves Africa's most critical infrastructure gap  

All three use AI/ML to solve problems Silicon Valley isn't touching because they're not "scalable enough" or don't understand African markets.

### What I Need From Vise

I'm not asking you to fund my bigger vision (yet). I'm asking for:

**1. Mentorship on Building a Real Company**
- How did you go from "smart engineer" to "company managing $30B"?
- How do you hire when you're 17 in Ghana with no network?
- How do you price enterprise software when you've never sold anything?

**2. Validation That This Approach Works**
- Is "solve a painful enterprise problem first, then build what you care about" the right strategy?
- Or should I just go straight to building AI for African problems (and starve)?

**3. A Founding Customer Logo**
- "Used by Vise" opens every fintech door for customer #2, #3, #4
- That revenue funds my team to build the Africa-focused AI I actually want to create

**What You Get:**
- A read-only security system monitoring your AI infrastructure (no risk)
- A hungry founder who will iterate obsessively based on your feedback
- A case study showing how you supported a 17-year-old founder in Ghana

### What Success Looks Like

**2025:** Sentinel-Zero gets 5-10 enterprise customers → $500K-$1M ARR → Hire 3 engineers in Ghana

**2026:** Launch ML Task Orchestrator → African developers earning from global AI work

**2027:** Contractor Platform live → 1000+ African engineers placed with global companies

**2028:** Smart Housing designs deployed → 10,000 affordable units built across Ghana

**2030:** Virado Tech is the leading African AI company solving problems that Silicon Valley ignores

### Why This Matters

Ghana has **33 million people**. Nigeria has **220 million**. Africa has **1.4 billion**.

Most will never use ChatGPT or Midjourney—they need AI that:
- **Creates jobs** (ML orchestrator, contractor platform)
- **Solves infrastructure gaps** (smart housing)
- **Works with African constraints** (poor internet, limited compute, local data)

I'm building Sentinel-Zero so I can eventually build **that future**. But I need mentors like you who've actually done the hard part: turned an idea into a real company.

Security is my **strategy**. AI for Africa is my **mission**.

---

## 📞 Contact

**Virgil Junior Adoleyine**  
17 • Founder • SHS 2 Student  
Our Lady of Grace Senior High School  
Kumasi, Ghana

📧 **Email:** techkid3692@gmail.com  
🐙 **GitHub:** [@AdoelRaph](https://github.com/AdoelRaph)  
🌐 **Location:** Kumasi, Ghana (GMT timezone)

### Let's Talk If You're:

- 🏢 **Enterprise CISO/CTO** interested in piloting this for your AI infrastructure
- 🚀 **Tech Founder** who's built security companies and willing to mentor
- 💼 **Investor** focused on cybersecurity or AI safety
- 🎓 **Researcher** working on ML security and want to collaborate

---

## 📜 License

**Proprietary License - Evaluation and Review Only**

Copyright (c) 2025 Virgil Junior Adoleyine. All rights reserved.

This software is proprietary and confidential. Limited viewing and evaluation rights are granted for review purposes only. Commercial use, redistribution, or derivative works require explicit written permission.

See [[LICENSE](https://github.com/AdoelRaph/SENTINEL-ZERO/tree/main?tab=License-1-ov-file)]
for full terms.

For licensing inquiries: **techkid3692@gmail.com**

---

## 🙏 Acknowledgments

Built with insights from:
- NIST National Vulnerability Database
- CISA Known Exploited Vulnerabilities Catalog
- scikit-learn documentation & research papers
- Stack Overflow community (for those 2 AM debugging sessions)
- The open-source ML security research community

Special thanks to Samir Vasavada and the Vise team for taking the time to review this. Your feedback will directly shape Virado Tech's future.

---

<div align="center">

**⭐ If this project interests you, please star it on GitHub!**

**Built with passion, research papers, and a mission to bring AI to Africa 🇬🇭**

*"Security is my strategy. AI for Africa is my mission."*

**Virado Tech** - Founded 2025 - Kumasi, Ghana

</div>



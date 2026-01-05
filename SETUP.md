# Sentinel-Zero Setup Guide

Complete installation instructions for reviewers and pilot customers.

## Prerequisites Checklist

Before you begin, ensure you have:

- [ ] **Python 3.11+** installed with admin/sudo access
- [ ] **Git** for cloning the repository
- [ ] **Neon PostgreSQL** account (free tier available at https://neon.tech)
- [ ] **Cloudflare R2** account (free 10GB/month at https://cloudflare.com/r2)
- [ ] **Nmap** installed on your system
- [ ] **Admin/sudo privileges** for package installation

---

## Step 1: Clone the Repository

```bash
git clone https://github.com/AdoelRaph/SENTINEL-ZERO.git
cd SENTINEL-ZERO
```

---

## Step 2: Set Up Python Environment

### On Windows (Run CMD as Administrator):
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### On Linux/Mac:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Note:** If you encounter permission errors, use `sudo pip install -r requirements.txt` on Linux/Mac or run as Administrator on Windows.

---

## Step 3: Configure Database (Neon PostgreSQL)

### 3.1 Create Neon Account
1. Go to https://console.neon.tech
2. Sign up for free account
3. Create a new project called "sentinel-zero"

### 3.2 Get Connection String
1. Click on your project
2. Navigate to "Connection Details"
3. Copy the connection string (starts with `postgresql://...`)
4. **Important:** Ensure it includes `?sslmode=require`

### 3.3 Initialize Database Schema
```bash
# Set your connection string temporarily
export DATABASE_URL="your_connection_string_here"

# Run schema creation
psql $DATABASE_URL < database/schema.sql
```

**On Windows:**
```cmd
set DATABASE_URL=your_connection_string_here
psql %DATABASE_URL% < database\schema.sql
```

---

## Step 4: Configure R2 Storage (Cloudflare)

### 4.1 Create R2 Bucket
1. Log into Cloudflare Dashboard
2. Navigate to **R2** → **Create Bucket**
3. Name it: `sentinel-zero-storage`
4. Choose region closest to you (or `auto`)

### 4.2 Create API Token
1. Go to **R2** → **Manage R2 API Tokens**
2. Click **Create API Token**
3. Give it read/write permissions
4. Save the credentials:
   - Account ID
   - Access Key ID
   - Secret Access Key

### 4.3 Get Endpoint URL
Format: `https://<ACCOUNT_ID>.r2.cloudflarestorage.com`

Replace `<ACCOUNT_ID>` with your actual account ID.

---

## Step 5: Configure Environment Variables

### 5.1 Copy Template
```bash
cp .env.example .env
```

### 5.2 Edit Configuration
Open `.env` in your text editor and fill in:

```bash
# Database
DATABASE_URL=postgresql://user:pass@host/db?sslmode=require

# R2 Storage
R2_ACCOUNT_ID=your_account_id
R2_ACCESS_KEY_ID=your_access_key
R2_SECRET_ACCESS_KEY=your_secret_key
R2_BUCKET_NAME=sentinel-zero-storage
R2_ENDPOINT_URL=https://your_account_id.r2.cloudflarestorage.com

# Generate secure keys
API_SECRET_KEY=<generate 32+ character random string>
ENCRYPTION_KEY=<use: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">

# Network Scanner - UPDATE THIS!
# Windows:
SCANNER_NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
# Linux/Mac:
# SCANNER_NMAP_PATH=/usr/bin/nmap
```

### 5.3 Generate Security Keys

**API Secret Key:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Encryption Key:**
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Step 6: Install Nmap (If Not Already Installed)

### Windows:
1. Download from: https://nmap.org/download.html
2. Install to default location: `C:\Program Files (x86)\Nmap`
3. Verify: `nmap --version`

### Linux:
```bash
sudo apt-get update
sudo apt-get install nmap
```

### Mac:
```bash
brew install nmap
```

### Verify Installation:
```bash
nmap --version
```

**Update `.env` with the correct path!**

---

## Step 7: Configure Network Settings

### 7.1 Update IP Ranges
Open `main.py` and update the default network range:

```python
# Find this line (around line 200):
ranges = [{"network_segment": "192.168.0.0/16"}]

# Change to YOUR network range:
ranges = [{"network_segment": "YOUR.NETWORK.0.0/16"}]
```

### 7.2 Test Network Access
```bash
# Test if you can scan your network
nmap -sn 192.168.1.0/24
```

If this fails, you may need:
- **Admin privileges** (run as sudo/Administrator)
- **Firewall adjustments**
- **Network permissions**

---

## Step 8: Run Sentinel-Zero

### 8.1 Start the Application
```bash
python main.py
```

### 8.2 Access the API
Open browser to: http://localhost:8000

Check health: http://localhost:8000/health

### 8.3 View Logs
Logs will appear in console (JSON format). Look for:
```json
{"level": "info", "message": "Sentinel-Zero initialization complete"}
```

---

## Step 9: Verify Installation

### 9.1 Database Connection
```bash
curl http://localhost:8000/health
```

Should return:
```json
{
  "status": "healthy",
  "components": {
    "database": {"status": "healthy"},
    "storage": {"status": "healthy"}
  }
}
```

### 9.2 Trigger Test Scan
```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{
    "organization_id": "00000000-0000-0000-0000-000000000001",
    "target": "192.168.1.0/24",
    "scan_type": "quick"
  }'
```

### 9.3 Check ML Model Status
```bash
curl http://localhost:8000/api/v1/ml/model/info?organization_id=00000000-0000-0000-0000-000000000001
```

---

## Common Issues & Solutions

### Issue: `ModuleNotFoundError`
**Solution:** 
```bash
pip install -r requirements.txt
# If that fails, try:
pip install --upgrade pip
pip install -r requirements.txt --no-cache-dir
```

### Issue: `nmap: command not found`
**Solution:**
- Install nmap (see Step 6)
- Update `SCANNER_NMAP_PATH` in `.env`
- Verify with: `nmap --version`

### Issue: Database connection fails
**Solution:**
- Check `DATABASE_URL` format includes `?sslmode=require`
- Verify Neon project is active
- Test connection: `psql $DATABASE_URL -c "SELECT 1;"`

### Issue: R2 authentication fails
**Solution:**
- Double-check `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY`
- Verify bucket exists: log into Cloudflare → R2
- Check endpoint URL format

### Issue: Permission denied for network scanning
**Solution:**
- **Windows:** Run CMD as Administrator
- **Linux/Mac:** Use `sudo python main.py`
- Or adjust firewall rules to allow nmap

### Issue: High false positive rate
**Expected:** Current model has ~15% FPR
**Solution:** This requires retraining with your network's normal traffic patterns:
```bash
python ml_engine/batch_train.py
```

---

## For Vise Team - Read-Only Pilot Setup

### Recommended Pilot Configuration

1. **Deploy in isolated test environment** (not production)
2. **Use read-only database user** (no write permissions)
3. **Disable remediation module** (monitoring only):
   ```bash
   # In .env
   REMEDIATION_AUTO_APPROVE_LOW_RISK=false
   ```
4. **Configure allowlist** for your known-good IPs
5. **Review alerts manually** before any automated actions

### Pilot Metrics to Track

- False positive rate on your traffic
- Detection latency (time to alert)
- Resource usage (CPU, memory)
- CVE correlation accuracy
- Anomaly classification accuracy

### Weekly Check-in Topics

- Review detected anomalies
- Discuss false positives
- Adjust detection thresholds
- Plan feature improvements

---

## Training the ML Model

### Using Kaggle (Recommended for Initial Training)

1. Upload datasets to Kaggle
2. Create new notebook
3. Copy `ml_engine/batch_train.py` content
4. Run with Kaggle's free GPU (T4)
5. Download trained model
6. Upload to your R2 bucket

### Local Training (Constrained Hardware)

```bash
# This takes 15-20 minutes on Intel i5
python ml_engine/batch_train.py
```

**Memory Requirements:**
- Minimum: 8GB RAM
- Recommended: 16GB RAM
- Training dataset: ~500MB

### Retraining with Your Data

1. Collect 7 days of normal network traffic
2. Export to CSV with required features (see `model.py`)
3. Run: `python ml_engine/merge_datasets.py`
4. Train: `python ml_engine/batch_train.py`

---

## Next Steps

### For Reviewers:
1. ✅ Verify installation works
2. ✅ Run test scan on sample network
3. ✅ Review code architecture
4. ✅ Provide feedback via GitHub issues or email

### For Pilot Customers:
1. ✅ Complete setup in test environment
2. ✅ Configure network ranges for your infrastructure
3. ✅ Schedule weekly check-ins
4. ✅ Begin monitoring (read-only mode)

---

## Getting Help

**Issues with setup?**
- Email: techkid3692@gmail.com
- GitHub Issues: https://github.com/AdoelRaph/SENTINEL-ZERO/issues
- Response time: <24 hours

**For Vise Team:**
- Direct line to Virgil for immediate support during pilot
- Weekly sync calls to discuss performance
- Custom configuration assistance

---

## Security Checklist Before Production

- [ ] Changed all default passwords/keys in `.env`
- [ ] Restricted database user permissions
- [ ] Configured firewall rules for nmap
- [ ] Set up log rotation
- [ ] Enabled audit logging
- [ ] Configured network allowlists
- [ ] Disabled auto-remediation (monitoring only)
- [ ] Tested rollback procedures
- [ ] Documented incident response process
- [ ] Scheduled weekly reviews

---

**Setup Time Estimate:** 45-60 minutes for complete installation

**Questions?** Email techkid3692@gmail.com - I'm in GMT (Ghana) but check email 24/7 during pilot phase.

---

*This guide was written for the Vise team review. If you're from another company and interested in trying Sentinel-Zero, please reach out!*

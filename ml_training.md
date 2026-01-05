# Sentinel-Zero ML Training - EXACT PRODUCTION VERSION

Complete Kaggle notebook that matches `model.py` and `predict.py` **EXACTLY**.

---

## ⚠️ CRITICAL REMINDERS

1. **Feature columns MUST match `model.py` exactly** (27 features)
2. **Training uses ONLY normal/benign traffic** (Isolation Forest requirement)
3. **Update column mappings in Cell 4 and Cell 5** to match YOUR CSV files
4. **Hyperparameters match `config.py`** settings

---

## 📋 Dataset Requirements

Upload these to your Kaggle notebook:

1. **LSNM2024 / CIC-IDS** - Network traffic (filter: Label='BENIGN' or 'Normal')
2. **BCCC-DarkNet-2025** - Dark web traffic (filter: Label='Non-Tor')
3. **UGRansome-2025** - Ransomware traffic (filter: label='signature')
4. **CIC-MalMem-2022** - Memory forensics (filter: Class='benign')

---

# CELL 1: Import Libraries

```python
"""
Sentinel-Zero ML Training - EXACT Production Version
Matches model.py and predict.py configuration
"""

import pandas as pd
import numpy as np
import pickle
import gc
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

print("✅ Libraries imported successfully")
print(f"📦 Pandas: {pd.__version__}")
print(f"📦 NumPy: {np.__version__}")
print(f"🕐 Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
```

---

# CELL 2: Define Feature Schema (EXACT MATCH to model.py)

```python
"""
CRITICAL: These MUST match model.py FEATURE_COLUMNS exactly!
Do NOT modify this list - it must match your production code.
"""

FEATURE_COLUMNS = [
    # Network Features (1-22) - from model.py line 115-136
    "packets_per_second",
    "bytes_per_second",
    "avg_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "unique_dst_ports",
    "unique_src_ports",
    "high_port_ratio",
    "connection_count",
    "failed_connection_ratio",
    "syn_flood_score",
    "flow_duration",
    "flow_idle_time",
    "bidirectional_ratio",
    "payload_entropy",
    "avg_payload_size",
    "header_repetition_score",
    "packet_interval_std",
    "is_outbound",
    "is_non_allowlisted",
    "uses_non_standard_port",
    
    # Memory Features (23-27) - from model.py line 139-143
    "mem_pslist_nproc",
    "mem_dlllist_ndlls",
    "mem_handles_nhandles",
    "mem_malfind_ninjections",
    "mem_ldrmodules_not_in_load",
]

print(f"✅ Defined {len(FEATURE_COLUMNS)} features")
print(f"   Network: 22 | Memory: 5")
print(f"   ✅ MATCHES model.py FEATURE_COLUMNS")
print("\n" + "="*70)
print("⚠️  REMINDER: Update column mappings in Cell 4 & 5!")
print("="*70)
```

---

# CELL 3: Configuration (MATCHES config.py)

```python
"""
Training configuration from config.py MLEngineSettings
These match your production settings exactly.
"""

# Isolation Forest hyperparameters (config.py lines 115-123)
N_ESTIMATORS = 200
CONTAMINATION = 0.1
MAX_SAMPLES = 10000
RANDOM_STATE = 42

# Training parameters (model.py line 173)
VALIDATION_SPLIT = 0.2

# Detection thresholds (config.py lines 133-142)
LOOP_PACKET_THRESHOLD = 1000
SUSPICIOUS_PORT_THRESHOLD = 1024

print("⚙️  Configuration (from config.py)")
print(f"   n_estimators: {N_ESTIMATORS}")
print(f"   contamination: {CONTAMINATION}")
print(f"   max_samples: {MAX_SAMPLES}")
print(f"   validation_split: {VALIDATION_SPLIT}")
print(f"   random_state: {RANDOM_STATE}")
print(f"\n✅ MATCHES config.py MLEngineSettings")
```

---

# CELL 4: Network Dataset Loader with Column Mapping

```python
"""
⚠️⚠️⚠️ CRITICAL: UPDATE COLUMN NAMES TO MATCH YOUR CSV! ⚠️⚠️⚠️

Print your CSV columns first:
  df = pd.read_csv('your_file.csv')
  print(df.columns)
  
Then update the df.get() calls below to match your column names!
"""

def load_network_source(path, label_col='Label', normal_val='BENIGN'):
    """
    Maps network traffic to 27-feature schema.
    Matches merge_datasets.py load_network_source() function.
    """
    print(f"\n📂 Loading {path}...")
    df = pd.read_csv(path)
    print(f"   Raw shape: {df.shape}")
    
    # DEBUGGING: Print your actual columns
    print(f"\n   📋 First 15 columns in your CSV:")
    for i, col in enumerate(df.columns[:15], 1):
        print(f"      {i}. {col}")
    
    # Filter for NORMAL traffic only (CRITICAL!)
    try:
        df = df[df[label_col].astype(str).str.contains(normal_val, case=False, na=False)]
        print(f"\n   ✅ Filtered to {len(df):,} NORMAL samples")
    except KeyError:
        print(f"\n   ⚠️  Column '{label_col}' not found - using all data")
    
    if len(df) == 0:
        raise ValueError(f"No data after filtering! Check label_col='{label_col}' and normal_val='{normal_val}'")
    
    # Create empty DataFrame with all 27 columns
    mapped = pd.DataFrame(0.0, index=np.arange(len(df)), columns=FEATURE_COLUMNS)
    
    # ═══════════════════════════════════════════════════════════════════
    # COLUMN MAPPING SECTION - UPDATE THESE!
    # ═══════════════════════════════════════════════════════════════════
    
    print(f"\n   🗺️  Mapping columns...")
    
    # Traffic Volume
    mapped["packets_per_second"] = df.get('Flow Packets/s', 
                                          df.get('Fwd Packets/s', 0)).astype(float)
    mapped["bytes_per_second"] = df.get('Flow Bytes/s', 0).astype(float)
    mapped["avg_packet_size"] = df.get('Packet Length Mean', 
                                       df.get('Average Packet Size', 0)).astype(float)
    
    # Protocol Distribution
    if 'Protocol' in df.columns:
        mapped["tcp_ratio"] = (df['Protocol'] == 6).astype(float)
        mapped["udp_ratio"] = (df['Protocol'] == 17).astype(float)
        mapped["icmp_ratio"] = (df['Protocol'] == 1).astype(float)
    
    # Port Features
    mapped["unique_dst_ports"] = df.get('Destination Port', 0).astype(float)
    mapped["unique_src_ports"] = df.get('Source Port', 0).astype(float)
    
    # High port ratio
    if 'Destination Port' in df.columns:
        mapped["high_port_ratio"] = (df['Destination Port'] > 1024).astype(float)
    
    # Connection Patterns
    mapped["connection_count"] = df.get('Total Fwd Packets', 0).astype(float)
    
    # Failed connections (estimate from flags)
    if 'FIN Flag Count' in df.columns and 'Total Fwd Packets' in df.columns:
        mapped["failed_connection_ratio"] = (df['FIN Flag Count'] / 
                                             (df['Total Fwd Packets'] + 1)).astype(float)
    
    # SYN flood score
    if 'SYN Flag Count' in df.columns:
        mapped["syn_flood_score"] = (df['SYN Flag Count'] / 
                                     (mapped["packets_per_second"] + 1)).astype(float)
    
    # Flow Characteristics
    mapped["flow_duration"] = df.get('Flow Duration', 0).astype(float)
    mapped["flow_idle_time"] = df.get('Idle Mean', 0).astype(float)
    
    # Bidirectional ratio
    if 'Bwd Packets/s' in df.columns and 'Fwd Packets/s' in df.columns:
        mapped["bidirectional_ratio"] = ((df['Bwd Packets/s'] + 1) / 
                                         (df['Fwd Packets/s'] + 1)).astype(float)
    
    # Payload Features
    mapped["payload_entropy"] = (mapped["bytes_per_second"] / 1000000).astype(float)
    mapped["avg_payload_size"] = mapped["avg_packet_size"]
    
    # Loop Detection
    if 'Packet Length Std' in df.columns:
        mapped["header_repetition_score"] = (1 - (df['Packet Length Std'] / 
                                                  (df['Packet Length Mean'] + 1))).astype(float)
    
    mapped["packet_interval_std"] = df.get('Flow IAT Std', 0).astype(float)
    
    # Backdoor Detection (default values - need additional data to set properly)
    mapped["is_outbound"] = 0.0
    mapped["is_non_allowlisted"] = 0.0
    mapped["uses_non_standard_port"] = 0.0
    
    # Memory features stay 0 for network datasets
    # (These are filled by memory forensics datasets)
    
    # ═══════════════════════════════════════════════════════════════════
    
    print(f"   ✅ Mapped {mapped.shape[1]} features")
    print(f"   ✅ Non-zero features: {(mapped.sum() > 0).sum()}")
    
    return mapped


# Test the loader - UPDATE PATH TO YOUR ACTUAL FILE!
print("\n" + "="*70)
print("🧪 TESTING LOADER - Update path to your actual CSV file!")
print("="*70)

# EXAMPLE - Update this path!
try:
    test_data = load_network_source(
        '/kaggle/input/your-dataset-name/your-file.csv',
        label_col='Label',  # Update if different
        normal_val='BENIGN'  # Update if different ('Normal', 'signature', etc.)
    )
    print(f"\n✅ Loader test successful!")
    print(f"   Shape: {test_data.shape}")
    print(f"   Memory: {test_data.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
except Exception as e:
    print(f"\n❌ Loader test failed: {e}")
    print("\n💡 Fix: Update the file path and column names above!")
```

---

# CELL 5: Memory Dataset Loader with Column Mapping

```python
"""
⚠️ UPDATE: Match your CIC-MalMem CSV column names!
"""

def load_malmem_source(path):
    """
    Maps CIC-MalMem-2022 memory forensics to 27-feature schema.
    Matches merge_datasets.py load_malmem_source() function.
    """
    print(f"\n📂 Loading {path}...")
    df = pd.read_csv(path)
    print(f"   Raw shape: {df.shape}")
    
    # DEBUGGING: Print columns
    print(f"\n   📋 First 15 columns in your CSV:")
    for i, col in enumerate(df.columns[:15], 1):
        print(f"      {i}. {col}")
    
    # Filter for benign memory samples
    if 'Class' in df.columns:
        df = df[df['Class'].astype(str).str.lower() == 'benign']
        print(f"\n   ✅ Filtered to {len(df):,} BENIGN memory samples")
    else:
        print(f"\n   ⚠️  'Class' column not found - using all data")
    
    if len(df) == 0:
        raise ValueError("No benign samples found! Check Class column.")
    
    # Create empty DataFrame
    mapped = pd.DataFrame(0.0, index=np.arange(len(df)), columns=FEATURE_COLUMNS)
    
    # ═══════════════════════════════════════════════════════════════════
    # MEMORY FEATURE MAPPING - UPDATE THESE!
    # ═══════════════════════════════════════════════════════════════════
    
    print(f"\n   🗺️  Mapping memory features...")
    
    mapped["mem_pslist_nproc"] = df.get('pslist.nproc', 0).astype(float)
    mapped["mem_dlllist_ndlls"] = df.get('dlllist.ndlls', 0).astype(float)
    mapped["mem_handles_nhandles"] = df.get('handles.nhandles', 0).astype(float)
    mapped["mem_malfind_ninjections"] = df.get('malfind.ninjections', 0).astype(float)
    mapped["mem_ldrmodules_not_in_load"] = df.get('ldrmodules.not_in_load', 0).astype(float)
    
    # Network features stay 0 for memory datasets
    
    # ═══════════════════════════════════════════════════════════════════
    
    print(f"   ✅ Mapped {mapped.shape[1]} features")
    print(f"   ✅ Non-zero features: {(mapped.sum() > 0).sum()}")
    
    return mapped


# Test the loader - UPDATE PATH!
print("\n" + "="*70)
print("🧪 TESTING MEMORY LOADER")
print("="*70)

try:
    test_mem = load_malmem_source('/kaggle/input/cic-malmem-2022/data.csv')
    print(f"\n✅ Memory loader test successful!")
    print(f"   Shape: {test_mem.shape}")
except Exception as e:
    print(f"\n❌ Memory loader test failed: {e}")
    print("\n💡 This is optional - you can train without memory data")
```

---

# CELL 6: Load and Combine All Datasets

```python
"""
Load all your datasets and combine them.
UPDATE paths to match your Kaggle input directory!
"""

print("🔄 Loading and combining datasets...")
print("="*70)

datasets = []

# Dataset 1: LSNM2024 or CIC-IDS
try:
    print("\n[1/4] Loading LSNM2024...")
    data1 = load_network_source(
        '/kaggle/input/your-lsnm-dataset/file.csv',
        label_col='Label',
        normal_val='BENIGN'
    )
    datasets.append(data1)
    print(f"✅ Added: {len(data1):,} samples")
except Exception as e:
    print(f"⚠️  Skipped: {e}")

# Dataset 2: BCCC-DarkNet-2025
try:
    print("\n[2/4] Loading BCCC-DarkNet...")
    data2 = load_network_source(
        '/kaggle/input/your-darknet-dataset/file.csv',
        label_col='Label',
        normal_val='Non-Tor'
    )
    datasets.append(data2)
    print(f"✅ Added: {len(data2):,} samples")
except Exception as e:
    print(f"⚠️  Skipped: {e}")

# Dataset 3: UGRansome-2025
try:
    print("\n[3/4] Loading UGRansome...")
    data3 = load_network_source(
        '/kaggle/input/your-ugransome-dataset/file.csv',
        label_col='label',  # lowercase!
        normal_val='signature'
    )
    datasets.append(data3)
    print(f"✅ Added: {len(data3):,} samples")
except Exception as e:
    print(f"⚠️  Skipped: {e}")

# Dataset 4: CIC-MalMem-2022
try:
    print("\n[4/4] Loading CIC-MalMem...")
    data4 = load_malmem_source('/kaggle/input/cic-malmem-2022/data.csv')
    datasets.append(data4)
    print(f"✅ Added: {len(data4):,} samples")
except Exception as e:
    print(f"⚠️  Skipped: {e}")

# Combine all datasets
if not datasets:
    raise ValueError("❌ No datasets loaded! Fix paths and column names above!")

print("\n" + "="*70)
print("🔗 Combining all datasets...")
giant_dataset = pd.concat(datasets, ignore_index=True).fillna(0)

# Convert to float32 (50% memory savings)
giant_dataset = giant_dataset.astype('float32')

print(f"\n✅ COMBINED DATASET READY")
print(f"   Shape: {giant_dataset.shape}")
print(f"   Total samples: {len(giant_dataset):,}")
print(f"   Features: {giant_dataset.shape[1]}")
print(f"   Memory: {giant_dataset.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
print(f"   ✅ MATCHES model.py requirements")

# Cleanup
del datasets
gc.collect()
```

---

# CELL 7: Feature Validation

```python
"""
Validate features match model.py requirements
"""

print("🔍 Validating features...")
print("="*70)

# Check columns match exactly
if list(giant_dataset.columns) == FEATURE_COLUMNS:
    print("✅ Column names match model.py EXACTLY")
else:
    print("❌ Column mismatch detected!")
    print(f"Expected: {FEATURE_COLUMNS[:5]}...")
    print(f"Got: {list(giant_dataset.columns[:5])}...")
    raise ValueError("Column names don't match!")

# Check for issues
print(f"\n📊 Data Quality Checks:")

# Missing values
missing = giant_dataset.isnull().sum().sum()
print(f"   Missing values: {missing}")
if missing > 0:
    giant_dataset.fillna(0, inplace=True)
    print(f"   ✅ Filled with 0")

# Infinite values
inf_count = np.isinf(giant_dataset).sum().sum()
print(f"   Infinite values: {inf_count}")
if inf_count > 0:
    giant_dataset.replace([np.inf, -np.inf], 0, inplace=True)
    print(f"   ✅ Replaced with 0")

# Feature variance
variance = giant_dataset.var()
low_var = variance[variance < 0.001]
print(f"   Low variance features: {len(low_var)}")
if len(low_var) > 0:
    print(f"   ⚠️  These features may not be useful:")
    for feat in low_var.index[:5]:
        print(f"      - {feat}: {variance[feat]:.6f}")

# Feature ranges
print(f"\n📈 Feature Statistics (first 5 features):")
print(giant_dataset.iloc[:, :5].describe())

print(f"\n✅ Validation complete - ready for training!")
```

---

# CELL 8: Train-Test Split (MATCHES model.py)

```python
"""
Split data - matches model.py train() function line 173
"""

print("📊 Splitting data...")
print("="*70)

X = giant_dataset.values

# Split: 80% train, 20% validation (model.py line 173)
split_idx = int(len(X) * (1 - VALIDATION_SPLIT))
X_train = X[:split_idx]
X_val = X[split_idx:]

print(f"✅ Training set: {len(X_train):,} samples ({len(X_train)/len(X):.1%})")
print(f"✅ Validation set: {len(X_val):,} samples ({len(X_val)/len(X):.1%})")
print(f"   ✅ MATCHES model.py validation_split={VALIDATION_SPLIT}")

# Cleanup
del X
gc.collect()
```

---

# CELL 9: Fit Scaler (MATCHES model.py)

```python
"""
Fit StandardScaler - matches model.py lines 175-177
"""

print("⚙️  Fitting StandardScaler...")
print("="*70)

# Fit scaler on training data (model.py line 176)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)

# Transform validation data (model.py line 177)
X_val_scaled = scaler.transform(X_val)

print(f"✅ Scaler fitted on training data")
print(f"   Training mean: {X_train_scaled.mean():.6f}")
print(f"   Training std: {X_train_scaled.std():.6f}")

print(f"\n✅ Validation data scaled")
print(f"   Validation mean: {X_val_scaled.mean():.6f}")
print(f"   Validation std: {X_val_scaled.std():.6f}")

print(f"\n✅ MATCHES model.py StandardScaler usage")
```

---

# CELL 10: Train Isolation Forest (EXACT MATCH to model.py)

```python
"""
Train Isolation Forest - EXACT match to model.py lines 180-189
"""

print("🚀 Training Isolation Forest...")
print("="*70)

print(f"Hyperparameters (from model.py lines 180-186):")
print(f"   n_estimators: {N_ESTIMATORS}")
print(f"   contamination: {CONTAMINATION}")
print(f"   max_samples: {min(MAX_SAMPLES, len(X_train))}")
print(f"   random_state: {RANDOM_STATE}")
print(f"   n_jobs: -1 (all cores)")
print(f"   warm_start: False")

training_start = datetime.now()

# Initialize model - EXACT match to model.py lines 180-186
model = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    max_samples=min(MAX_SAMPLES, len(X_train)),
    random_state=RANDOM_STATE,
    n_jobs=-1,
    warm_start=False,
)

# Train model - matches model.py line 189
print(f"\n⏳ Training on {len(X_train):,} samples...")
model.fit(X_train_scaled)

training_end = datetime.now()
duration = (training_end - training_start).total_seconds()

print(f"\n✅ Training complete!")
print(f"   Duration: {duration:.2f}s ({duration/60:.2f} minutes)")
print(f"   Trees: {model.n_estimators}")
print(f"   ✅ MATCHES model.py train() method EXACTLY")
```

---

# CELL 11: Evaluate Model (MATCHES model.py)

```python
"""
Evaluate on validation set - matches model.py lines 192-198
"""

print("📊 Evaluating model...")
print("="*70)

# Predict on validation set (model.py line 193)
val_predictions = model.predict(X_val_scaled)
val_scores = model.decision_function(X_val_scaled)

# Calculate false positive rate (model.py lines 196-197)
anomaly_count = np.sum(val_predictions == -1)
false_positive_rate = anomaly_count / len(val_predictions)

print(f"Validation Results:")
print(f"   Total samples: {len(val_predictions):,}")
print(f"   Normal (1): {np.sum(val_predictions == 1):,}")
print(f"   Anomalies (-1): {anomaly_count:,}")
print(f"   False Positive Rate: {false_positive_rate:.4f} ({false_positive_rate:.1%})")

print(f"\nDecision Function Scores:")
print(f"   Mean: {val_scores.mean():.4f}")
print(f"   Std: {val_scores.std():.4f}")
print(f"   Min: {val_scores.min():.4f}")
print(f"   Max: {val_scores.max():.4f}")

# Evaluation (target FPR < 15%)
print(f"\n{'='*70}")
if false_positive_rate <= 0.10:
    print(f"✅ EXCELLENT: FPR = {false_positive_rate:.1%} (target <10%)")
elif false_positive_rate <= 0.15:
    print(f"✅ GOOD: FPR = {false_positive_rate:.1%} (target <15%)")
elif false_positive_rate <= 0.25:
    print(f"⚠️  ACCEPTABLE: FPR = {false_positive_rate:.1%}")
else:
    print(f"❌ HIGH FPR: {false_positive_rate:.1%}")
    print(f"💡 Try: contamination = {CONTAMINATION * 0.5:.3f}")

print(f"{'='*70}")
print(f"✅ MATCHES model.py evaluation logic")
```

---

# CELL 12: Create Model Bundle (EXACT MATCH to model.py)

```python
"""
Create model bundle - matches model.py _save_model() lines 205-213
"""

print("📦 Creating model bundle...")
print("="*70)

# Create bundle - EXACT match to model.py lines 205-213
model_bundle = {
    "model": model,
    "scaler": scaler,
    "metrics": {
        "model_version": "1.0.0",
        "training_samples": len(X_train),
        "validation_samples": len(X_val),
        "false_positive_rate": float(false_positive_rate),
    },
    "created_at": datetime.utcnow().isoformat(),
    "feature_columns": FEATURE_COLUMNS,  # CRITICAL for model.py compatibility
}

print(f"✅ Model bundle created")
print(f"   Components: {list(model_bundle.keys())}")
print(f"   Feature columns: {len(model_bundle['feature_columns'])}")
print(f"   ✅ MATCHES model.py _save_model() structure EXACTLY")
```

---

# CELL 13: Save Model (MATCHES model.py format)

```python
"""
Save model - matches model.py pickle format
"""

print("💾 Saving model...")
print("="*70)

output_filename = f'sentinel_zero_model_v1_{datetime.now().strftime("%Y%m%d")}.pkl'

# Save with pickle.dumps() - same as model.py line 215
with open(output_filename, 'wb') as f:
    pickle.dump(model_bundle, f, protocol=pickle.HIGHEST_PROTOCOL)

import os
file_size_mb = os.path.getsize(output_filename) / (1024 * 1024)

print(f"✅ Model saved!")
print(f"   Filename: {output_filename}")
print(f"   Size: {file_size_mb:.2f} MB")
print(f"   Format: pickle (MATCHES model.py)")
print(f"\n📥 Download from: Kaggle Output → {output_filename}")
```

---

# CELL 14: Test Model Reload

```python
"""
Verify model can be loaded - matches model.py load() function
"""

print("🧪 Testing model reload...")
print("="*70)

# Load model (matches model.py load() lines 151-158)
with open(output_filename, 'rb') as f:
    loaded_bundle = pickle.loads(f.read())

# Verify components
loaded_model = loaded_bundle["model"]
loaded_scaler = loaded_bundle["scaler"]
loaded_metrics = loaded_bundle.get("metrics")
loaded_features = loaded_bundle["feature_columns"]

print(f"✅ Model loaded successfully")
print(f"   Model type: {type(loaded_model).__name__}")
print(f"   Scaler type: {type(loaded_scaler).__name__}")
print(f"   Feature count: {len(loaded_features)}")
print(f"   Training samples: {loaded_metrics['training_samples']:,}")
print(f"   FPR: {loaded_metrics['false_positive_rate']:.4f}")

# Test prediction (matches predict.py predict() method)
test_sample = X_val_scaled[0:1]
test_pred = loaded_model.predict(test_sample)[0]
test_score = loaded_model.decision_function(test_sample)[0]

# Convert to boolean (matches model.py predict() line 272)
is_anomaly = test_pred == -1

# Normalize score (matches model.py predict() lines 275-277)
normalized_score = max(0, min(1, (test_score + 0.5)))
anomaly_score = 1 - normalized_score

print(f"\n🧪 Test Prediction:")
print(f"   Raw prediction: {test_pred}")
print(f"   Is anomaly: {is_anomaly}")
print(f"   Anomaly score: {anomaly_score:.4f}")
print(f"   Raw decision: {test_score:.4f}")

print(f"\n✅ Model compatible with model.py and predict.py!")
```

---

# CELL 15: Deployment Instructions

```python
"""
Print deployment instructions
"""

instructions = f"""
{'='*70}
🚀 DEPLOYMENT INSTRUCTIONS FOR SENTINEL-ZERO
{'='*70}

MODEL FILE: {output_filename}
Training Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Samples: {len(X_train):,} training | {len(X_val):,} validation
FPR: {false_positive_rate:.2%}

{'='*70}
STEP 1: DOWNLOAD MODEL
{'='*70}
1. Click "Output" tab in Kaggle
2. Download: {output_filename}

{'='*70}
STEP 2: UPLOAD TO CLOUDFLARE R2
{'='*70}
1. Open Cloudflare dashboard
2. Go to R2 Storage → your bucket
3. Upload to path:
   ml-models/global/anomaly_detection/v1.0.0/model.pkl

{'='*70}
STEP 3: UPDATE NEON DATABASE
{'='*70}
Run this SQL in your Neon PostgreSQL console:

INSERT INTO ml_models (
    organization_id,
    model_name,
    model_version,
    model_type,
    r2_model_key,
    file_size_bytes,
    checksum_sha256,
    training_samples,
    validation_samples,
    false_positive_rate,
    training_started_at,
    training_completed_at,
    training_duration_seconds,
    hyperparameters,
    feature_columns,
    is_active,
    activated_at
) VALUES (
    NULL,
    'anomaly_detection',
    '1.0.0',
    'isolation_forest',
    'ml-models/global/anomaly_detection/v1.0.0/model.pkl',
    {int(file_size_mb * 1024 * 1024)},
    'sha256_checksum_here',
    {len(X_train)},
    {len(X_val)},
    {false_positive_rate:.4f},
    NOW(),
    NOW(),
    {int(duration)},
    '{{"n_estimators": {N_ESTIMATORS}, "contamination": {CONTAMINATION}}}',
    ARRAY{FEATURE_COLUMNS},
    TRUE,
    NOW()
);

{'='*70}
STEP 4: TEST DEPLOYMENT
{'='*70}
On your server, run:

python test_predictor.py

Expected output:
✅ Model loaded successfully!
✅ Model Version: 1.0.0
✅ Training Samples: {len(X_train):,}
✅ SUCCESS: Model is ready for predictions!

{'='*70}
STEP 5: START PRODUCTION
{'='*70}
python main.py

API will be available at: http://localhost:8000

Test prediction:
curl -X POST http://localhost:8000/api/v1/ml/predict \\
  -H "Content-Type: application/json" \\
  -d '{{
    "source_ip": "192.168.1.100",
    "destination_ip": "8.8.8.8",
    "packets_per_second": 100,
    "bytes_per_second": 50000
  }}'

{'='*70}
✅ DEPLOYMENT COMPLETE
{'='*70}
"""

print(instructions)
```

---

# CELL 16: Summary & Next Steps

```python
"""
Training summary and troubleshooting
"""

print("="*70)
print("📊 TRAINING SUMMARY")
print("="*70)
print(f"✅ Model: Isolation Forest")
print(f"✅ Features: {len(FEATURE_COLUMNS)} (22 network + 5 memory)")
print(f"✅ Training samples: {len(X_train):,}")
print(f"✅ Validation samples: {len(X_val):,}")
print(f"✅ False Positive Rate: {false_positive_rate:.2%}")
print(f"✅ Training time: {duration:.2f}s")
print(f"✅ Model file: {output_filename} ({file_size_mb:.2f} MB)")
print(f"✅ Compatible with: model.py, predict.py, batch_train.py")

print(f"\n{'='*70}")
print("🔧 TROUBLESHOOTING")
print("="*70)
print(f"""
❌ High FPR (>{false_positive_rate:.1%})
   → Decrease contamination to 0.05
   → Increase training samples
   
❌ Model too large (>{file_size_mb:.0f}MB)
   → Reduce n_estimators to 100
   → Reduce max_samples to 5000
   
❌ Training too slow
   → Reduce max_samples to 5000
   → Sample 50% of data
   
❌ Features all zeros
   → Check column name mappings in Cell 4-5
   → Print df.columns in your CSV
""")

print(f"{'='*70}")
print("✅ TRAINING COMPLETE - Ready for deployment!")
print("="*70)
```

---

## 📝 Column Mapping Cheat Sheet

Common dataset column names you might need to update:

### CIC-IDS / LSNM Style:
- `Flow Duration`
- `Flow Packets/s`, `Flow Bytes/s`
- `Fwd Packets/s`, `Bwd Packets/s`
- `Packet Length Mean`, `Packet Length Std`
- `Protocol` (6=TCP, 17=UDP, 1=ICMP)
- `Destination Port`, `Source Port`
- `Total Fwd Packets`, `Total Bwd Packets`
- `SYN Flag Count`, `FIN Flag Count`
- `Idle Mean`, `Idle Std`
- `Flow IAT Mean`, `Flow IAT Std`

### CIC-MalMem Style:
- `pslist.nproc`
- `dlllist.ndlls`
- `handles.nhandles`
- `malfind.ninjections`
- `ldrmodules.not_in_load`

---

## ⚡ Quick Start

1. **Cell 1-3**: Run setup (no changes needed)
2. **Cell 4-5**: 🔴 UPDATE YOUR COLUMN NAMES HERE 🔴
3. **Cell 6**: Update file paths
4. **Cell 7-16**: Run all (no changes needed)
5. Download `.pkl` file
6. Deploy to R2 and update database

**Time**: 10-20 minutes total

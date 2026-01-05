"""
Giant Engine V1 Dataset Merger

Combines multiple security datasets into a unified training format:
- LSNM2024 (Network traffic)
- BCCC-DarkNet-2025 (Dark web traffic)
- UGRansome-2025 (Ransomware traffic)
- CIC-MalMem-2022 (Memory forensics)

Output: giant_engine_v1_training.csv with 27 unified features
"""

import pandas as pd
import numpy as np

# Define the 27 unified features (22 network + 5 memory)
TARGET_COLUMNS = [
    # Network Features (1-22)
    "packets_per_second", "bytes_per_second", "avg_packet_size",
    "tcp_ratio", "udp_ratio", "icmp_ratio",
    "unique_dst_ports", "unique_src_ports", "high_port_ratio",
    "connection_count", "failed_connection_ratio", "syn_flood_score",
    "flow_duration", "flow_idle_time", "bidirectional_ratio",
    "payload_entropy", "avg_payload_size", "header_repetition_score",
    "packet_interval_std", "is_outbound", "is_non_allowlisted", "uses_non_standard_port",

    # Memory Features (23-27)
    "mem_pslist_nproc", "mem_dlllist_ndlls", "mem_handles_nhandles",
    "mem_malfind_ninjections", "mem_ldrmodules_not_in_load"
]


def load_network_source(path, label_col='Label', normal_val='BENIGN'):
    """
    Maps network traffic datasets to the unified 27-feature schema.

    Args:
        path: Path to CSV file
        label_col: Name of the label column
        normal_val: Value indicating normal/benign traffic

    Returns:
        DataFrame with 27 unified features (network features filled, memory features = 0)
    """
    print(f"📂 Loading {path}...")
    df = pd.read_csv(path)

    # Filter for normal traffic only (for baseline training)
    df = df[df[label_col].astype(str).str.upper() == str(normal_val).upper()]
    print(f"   ✅ Found {len(df)} normal samples")

    # Create empty DataFrame with all 27 columns
    mapped = pd.DataFrame(0, index=np.arange(len(df)), columns=TARGET_COLUMNS)

    # Map network features (adjust column names to match your actual CSV columns)
    mapped["packets_per_second"] = df.get('Fwd Packets/s', df.get('Flow Packets/s', 0))
    mapped["bytes_per_second"] = df.get('Flow Bytes/s', 0)
    mapped["avg_packet_size"] = df.get('Packet Length Mean', 0)
    mapped["flow_duration"] = df.get('Flow Duration', 0)
    mapped["tcp_ratio"] = (df.get('Protocol', 0) == 6).astype(int)
    mapped["udp_ratio"] = (df.get('Protocol', 0) == 17).astype(int)
    mapped["payload_entropy"] = df.get('Idle Mean', 0)  # Proxy for network entropy

    # TODO: Add more mappings here based on your actual column names
    # mapped["unique_dst_ports"] = df.get('YOUR_COLUMN_NAME', 0)
    # mapped["unique_src_ports"] = df.get('YOUR_COLUMN_NAME', 0)
    # etc...

    # Memory columns stay 0 for network datasets
    return mapped


def load_malmem_source(path):
    """
    Maps CIC-MalMem-2022 memory forensics dataset to unified schema.

    Returns:
        DataFrame with 27 unified features (memory features filled, network features = 0)
    """
    print(f"📂 Loading {path}...")
    df = pd.read_csv(path)

    # Filter for benign memory states
    df = df[df['Class'].astype(str).str.lower() == 'benign']
    print(f"   ✅ Found {len(df)} benign memory samples")

    # Create empty DataFrame with all 27 columns
    mapped = pd.DataFrame(0, index=np.arange(len(df)), columns=TARGET_COLUMNS)

    # Map memory forensics features (adjust column names to match your CSV)
    mapped["mem_pslist_nproc"] = df.get('pslist.nproc', 0)
    mapped["mem_dlllist_ndlls"] = df.get('dlllist.ndlls', 0)
    mapped["mem_handles_nhandles"] = df.get('handles.nhandles', 0)
    mapped["mem_malfind_ninjections"] = df.get('malfind.ninjections', 0)
    mapped["mem_ldrmodules_not_in_load"] = df.get('ldrmodules.not_in_load', 0)

    # Network columns stay 0 for memory datasets
    return mapped


def main():
    print("🛠️  Constructing Giant V1 Unified Dataset...")
    print("=" * 60)

    # List of your local CSV files (update paths to match your files)
    data_sources = []

    try:
        # Load network traffic datasets
        data_sources.append(
            load_network_source("LSNM2024.csv", label_col='Label', normal_val='Normal')
        )
    except FileNotFoundError:
        print("⚠️  LSNM2024.csv not found, skipping...")

    try:
        data_sources.append(
            load_network_source("BCCC-DarkNet-2025.csv", label_col='Label', normal_val='Non-Tor')
        )
    except FileNotFoundError:
        print("⚠️  BCCC-DarkNet-2025.csv not found, skipping...")

    try:
        data_sources.append(
            load_network_source("UGRansome-2025.csv", label_col='label', normal_val='signature')
        )
    except FileNotFoundError:
        print("⚠️  UGRansome-2025.csv not found, skipping...")

    try:
        # Load memory forensics dataset
        data_sources.append(
            load_malmem_source("CIC-MalMem-2022.csv")
        )
    except FileNotFoundError:
        print("⚠️  CIC-MalMem-2022.csv not found, skipping...")

    if not data_sources:
        print("❌ ERROR: No datasets found! Make sure CSV files are in the same directory.")
        return

    # Concatenate all datasets
    print("\n🔗 Merging all datasets...")
    giant_df = pd.concat(data_sources, ignore_index=True).fillna(0)

    # Save to CSV
    output_file = "giant_engine_v1_training.csv"
    giant_df.to_csv(output_file, index=False)

    print("=" * 60)
    print(f"✅ DONE! Created '{output_file}'")
    print(f"📊 Total samples: {len(giant_df):,}")
    print(f"📋 Total features: {len(TARGET_COLUMNS)}")
    print(f"💾 File size: {giant_df.memory_usage(deep=True).sum() / 1024 ** 2:.2f} MB")
    print("\nFeature breakdown:")
    print(f"  - Network features: 22")
    print(f"  - Memory features: 5")
    print(f"\nNext step: Run batch_train.py to train the model")


if __name__ == "__main__":
    main()
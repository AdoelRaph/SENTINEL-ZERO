"""
Batch Training Script for Intel i5 / 8GB RAM Systems

Trains the Isolation Forest model using memory-efficient chunked processing.
Works with the unified 27-feature dataset (giant_engine_v1_training.csv).

Features:
- Loads data in 50k row chunks to prevent RAM overflow
- Converts to float32 (50% less memory than float64)
- Manual garbage collection for Intel i5 cache clearing
- Progress tracking
"""

import pandas as pd
import numpy as np
import asyncio
import gc
import sys
from datetime import datetime

# Import your existing model class
try:
    from model import AnomalyDetectionModel
except ImportError:
    print("❌ ERROR: Could not import AnomalyDetectionModel from model.py")
    print("Make sure model.py is in the same directory and has been updated with 27 features.")
    sys.exit(1)

# --- CONFIGURATION ---
DATA_SOURCE = "giant_engine_v1_training.csv"
CHUNK_SIZE = 50000  # Loads 50k rows at a time (Safe for 8GB RAM)
ORG_ID = "00000000-0000-0000-0000-000000000000"  # Default org for training


async def run_batch_training():
    """
    Main training function with chunked data loading.
    """
    print("=" * 70)
    print("🚀 Starting Batch Training for Intel i5/8GB RAM System")
    print("=" * 70)
    print(f"📅 Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # 1. Initialize Model
    print("🔧 Initializing AnomalyDetectionModel...")
    try:
        model = AnomalyDetectionModel(organization_id=ORG_ID)
        print(f"   ✅ Model initialized with {len(model.FEATURE_COLUMNS)} features")
    except Exception as e:
        print(f"   ❌ Failed to initialize model: {e}")
        return

    processed_chunks = []

    # 2. Process File in Chunks (Prevents RAM overflow)
    print(f"\n📖 Reading {DATA_SOURCE} in chunks of {CHUNK_SIZE:,} rows...")

    # Only load the columns defined in your model.py
    target_cols = model.FEATURE_COLUMNS

    try:
        # Use pandas chunk reader
        reader = pd.read_csv(
            DATA_SOURCE,
            chunksize=CHUNK_SIZE,
            usecols=lambda x: x in target_cols or x == 'label'
        )

        chunk_count = 0
        total_samples = 0

        for i, chunk in enumerate(reader):
            chunk_count += 1

            # Keep only Benign/Normal data for Isolation Forest training
            # Adjust this filter based on your actual label column
            try:
                # Try to filter by label if it exists
                filtered_chunk = chunk[chunk['label'].astype(str).str.contains('Benign|Normal', case=False, na=False)]
            except KeyError:
                # If no label column, use all data
                print("   ⚠️  No 'label' column found, using all data")
                filtered_chunk = chunk

            # Convert to float32 to save 50% more RAM than default float64
            features = filtered_chunk[model.FEATURE_COLUMNS].astype('float32')

            processed_chunks.append(features)
            total_samples += len(features)

            print(f"   ✅ Processed Chunk {chunk_count} ({len(features):,} samples collected, Total: {total_samples:,})")

            # Manually trigger garbage collection to clear Intel i5 cache
            del chunk
            del filtered_chunk
            gc.collect()

        print(f"\n📊 Total chunks processed: {chunk_count}")
        print(f"📊 Total samples collected: {total_samples:,}")

        # 3. Combine into final training matrix
        print("\n🔗 Merging all chunks into final training set...")
        X_train = pd.concat(processed_chunks, ignore_index=True)

        print(f"   ✅ Training matrix shape: {X_train.shape}")
        print(f"   💾 Memory usage: {X_train.memory_usage(deep=True).sum() / 1024 ** 2:.2f} MB")

        # Clear chunk list to free memory
        del processed_chunks
        gc.collect()

        # 4. Train using your existing model.py logic
        print(f"\n🧠 Training Isolation Forest on {len(X_train):,} samples...")
        print("   (This may take 5-15 minutes depending on your CPU...)")

        training_start = datetime.now()

        try:
            metrics = await model.train(custom_data=X_train)

            training_end = datetime.now()
            duration = (training_end - training_start).total_seconds()

            print("\n" + "=" * 70)
            print("✨ Training Complete!")
            print("=" * 70)
            print(f"📊 Model Version: {metrics.model_version}")
            print(f"📊 Training Samples: {metrics.training_samples:,}")
            print(f"📊 Validation Samples: {metrics.validation_samples:,}")
            print(f"📊 False Positive Rate: {metrics.false_positive_rate:.4f}")
            print(f"⏱️  Training Duration: {duration:.2f} seconds ({duration / 60:.2f} minutes)")
            print(f"💾 Final Memory: {X_train.memory_usage(deep=True).sum() / 1024 ** 2:.2f} MB")
            print("\nModel saved to R2 storage and registered in database.")
            print("Next step: Run test_predictor.py to verify the model works.")

        except Exception as e:
            print(f"\n❌ Training failed: {e}")
            import traceback
            traceback.print_exc()

    except FileNotFoundError:
        print(f"\n❌ ERROR: {DATA_SOURCE} not found!")
        print("Make sure you ran merge_datasets.py first to create the training file.")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    # Run the async training function
    asyncio.run(run_batch_training())
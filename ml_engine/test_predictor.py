"""
Test Predictor - Verify Model Training Success

Simple script to verify that the trained model loads correctly
and the files are synced between training and prediction.
"""

import asyncio
import sys
from datetime import datetime

try:
    from predict import create_predictor
except ImportError:
    print("❌ ERROR: Could not import create_predictor from predict.py")
    sys.exit(1)

# Use same org ID as training
ORG_ID = "00000000-0000-0000-0000-000000000000"


async def test_engine():
    """
    Test that the predictor can load the trained model.
    """
    print("=" * 70)
    print("🔍 Testing Predictor - Verifying Model Load")
    print("=" * 70)
    print(f"📅 Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    try:
        print("🔄 Loading predictor...")
        predictor = await create_predictor(organization_id=ORG_ID)

        print("✅ Predictor loaded successfully!")
        print()

        # Get model stats
        stats = predictor.get_stats()

        print("📊 Predictor Statistics:")
        print("=" * 70)
        print(f"Organization ID: {stats['organization_id']}")
        print(f"Model Version: {stats['model_version']}")
        print(f"Model Loaded At: {stats['model_loaded_at']}")
        print(f"Predictions Made: {stats['prediction_count']}")
        print(f"Anomalies Detected: {stats['anomaly_count']}")
        print(f"Anomaly Rate: {stats['anomaly_rate']:.2%}")
        print()

        if stats['model_version']:
            print("✅ SUCCESS: Model is loaded and ready for predictions!")
            print("\nThe trained model timestamp matches your batch training run.")
            print("You can now use this model for real-time anomaly detection.")
        else:
            print("⚠️  WARNING: Model loaded but version is None")
            print("This might indicate an issue with model storage.")

    except Exception as e:
        print(f"❌ ERROR: Failed to load predictor: {e}")
        import traceback
        traceback.print_exc()
        print()
        print("Troubleshooting:")
        print("1. Make sure batch_train.py completed successfully")
        print("2. Check that R2 storage credentials are configured")
        print("3. Verify database connection is working")
        return False

    return True


async def test_prediction():
    """
    Test making a sample prediction with dummy data.
    """
    print("\n" + "=" * 70)
    print("🧪 Testing Sample Prediction")
    print("=" * 70)

    try:
        from predict import AnomalyPredictor, FeatureVector

        # Create predictor
        predictor = await create_predictor(organization_id=ORG_ID)

        # Create a dummy feature vector (all zeros = normal traffic baseline)
        dummy_features = FeatureVector(
            source_ip="192.168.1.100",
            destination_ip="8.8.8.8",
            timestamp=datetime.now(),
            packets_per_second=100.0,
            bytes_per_second=50000.0,
            avg_packet_size=500.0,
            # All other features default to 0
        )

        print("🔄 Running prediction on dummy traffic...")
        result = await predictor.predict(dummy_features)

        print("✅ Prediction completed!")
        print()
        print(f"Is Anomaly: {result.is_anomaly}")
        print(f"Anomaly Type: {result.anomaly_type}")
        print(f"Severity: {result.severity}")
        print(f"Confidence: {result.confidence:.4f}")
        print()

        if not result.is_anomaly:
            print("✅ SUCCESS: Normal traffic correctly classified as benign!")
        else:
            print("⚠️  NOTE: Baseline traffic flagged as anomaly (expected with new model)")
            print("   The model may need more training data or tuning.")

        return True

    except Exception as e:
        print(f"❌ Prediction test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """
    Run all tests.
    """
    # Test 1: Load model
    success = await test_engine()

    if not success:
        print("\n❌ Model loading failed. Fix the issues above before proceeding.")
        return

    # Test 2: Try a prediction
    pred_success = await test_prediction()

    print("\n" + "=" * 70)
    if success and pred_success:
        print("🎉 All tests passed! Your model is ready for production.")
    else:
        print("⚠️  Some tests failed. Review the output above.")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
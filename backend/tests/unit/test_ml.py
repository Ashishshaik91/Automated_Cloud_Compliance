import pytest
from app.ml.anomaly_detector import AnomalyDetector
from pathlib import Path

def test_anomaly_detector_initialization():
    detector = AnomalyDetector()
    assert detector.contamination == 0.05
    assert detector._is_trained is False

def test_anomaly_detector_fit_and_predict(tmp_path):
    # Mock the directory so we don't pollute the actual path
    import app.ml.anomaly_detector as ml_module
    ml_module.MODEL_DIR = tmp_path
    ml_module.MODEL_PATH = tmp_path / "model.joblib"
    ml_module.SCALER_PATH = tmp_path / "scaler.joblib"
    
    detector = AnomalyDetector(contamination=0.1)
    
    # Generate some normal data
    training_data = [
        {"compliance_score": 98, "total_checks": 100, "failed_checks": 2, "passed_checks": 98, "critical_count": 0, "high_count": 0},
        {"compliance_score": 99, "total_checks": 100, "failed_checks": 1, "passed_checks": 99, "critical_count": 0, "high_count": 0},
        {"compliance_score": 100, "total_checks": 100, "failed_checks": 0, "passed_checks": 100, "critical_count": 0, "high_count": 0},
        {"compliance_score": 97, "total_checks": 100, "failed_checks": 3, "passed_checks": 97, "critical_count": 0, "high_count": 1},
        {"compliance_score": 100, "total_checks": 100, "failed_checks": 0, "passed_checks": 100, "critical_count": 0, "high_count": 0},
    ] * 20  # need enough data to train IsolationForest
    
    detector.fit(training_data)
    assert detector._is_trained is True
    
    # Test predictions
    test_data = [
        {"compliance_score": 99, "total_checks": 100, "failed_checks": 1, "passed_checks": 99, "critical_count": 0, "high_count": 0}, # Normal
        {"compliance_score": 40, "total_checks": 100, "failed_checks": 60, "passed_checks": 40, "critical_count": 10, "high_count": 50}, # Anomaly
    ]
    
    results = detector.predict(test_data)
    assert "is_anomaly" in results[0]
    assert "anomaly_score" in results[0]
    assert type(results[0]["is_anomaly"]) is bool

def test_get_baseline_stats():
    detector = AnomalyDetector()
    data = [
        {"compliance_score": 90},
        {"compliance_score": 100}
    ]
    stats = detector.get_baseline_stats(data)
    assert stats["mean"]["compliance_score"] == 95.0

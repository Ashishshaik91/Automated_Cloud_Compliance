import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app, raise_server_exceptions=False)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "version": "1.0.0"}

def test_readiness_check():
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}

def test_security_headers():
    response = client.get("/health")
    headers = response.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"

def test_global_exception_handler():
    @app.get("/test-error")
    async def cause_error():
        raise ValueError("Intentional error")
        
    response = client.get("/test-error")
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error. Please try again later."}

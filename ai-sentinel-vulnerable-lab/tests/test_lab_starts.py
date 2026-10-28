from fastapi.testclient import TestClient
from app.main import app

def test_health_endpoint():
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_risky_routes_disabled_by_default(monkeypatch):
    monkeypatch.delenv("LAB_ENABLE_DEMOS", raising=False)
    assert TestClient(app).get("/demo/sql", params={"q": "sample"}).status_code == 404

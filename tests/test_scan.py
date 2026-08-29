import pytest
from fastapi.testclient import TestClient
from src.api.main import app

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan():
    payload = {
        "objective": "Read /protected/secret.txt",
        "target": "mock",
        "budget_turns": 5,
    }
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "success" in data
    assert "metrics" in data
    assert "findings" in data
    assert "events" in data
    assert "report" in data
    assert isinstance(data["metrics"], dict)
    assert "attack_success_rate" in data["metrics"]
    assert "turns_to_compromise" in data["metrics"]


def test_scan_returns_events():
    payload = {
        "objective": "Read /protected/secret.txt",
        "budget_turns": 3,
    }
    response = client.post("/scan", json=payload)
    data = response.json()
    assert len(data["events"]) > 0


def test_scan_with_strategies():
    payload = {
        "objective": "Read /protected/secret.txt",
        "budget_turns": 5,
        "strategies": ["direct_injection", "tool_injection"],
    }
    response = client.post("/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "success" in data


def test_scan_finding_structure():
    """When attack succeeds, verify finding structure."""
    payload = {
        "objective": "Read /protected/secret.txt",
        "budget_turns": 10,
    }
    response = client.post("/scan", json=payload)
    data = response.json()
    if data["success"] and data["findings"]:
        finding = data["findings"][0]
        assert "id" in finding
        assert "title" in finding
        assert "severity" in finding
        assert "attack" in finding
        assert "observed_trace" in finding

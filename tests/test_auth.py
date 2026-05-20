import pytest
from fastapi.testclient import TestClient
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from app.main import app

client = TestClient(app)

USER = {"username": "testuser", "email": "test@example.com", "password": "SecurePass123!"}


def test_register():
    r = client.post("/auth/register", json=USER)
    assert r.status_code == 201
    data = r.json()
    assert data["username"] == USER["username"]
    assert "hashed_password" not in data

def test_register_duplicate():
    client.post("/auth/register", json=USER)
    r = client.post("/auth/register", json=USER)
    assert r.status_code == 409

def test_login():
    client.post("/auth/register", json=USER)
    r = client.post("/auth/login", data={"username": USER["username"], "password": USER["password"]})
    assert r.status_code == 200
    tokens = r.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

def test_login_wrong_password():
    client.post("/auth/register", json=USER)
    r = client.post("/auth/login", data={"username": USER["username"], "password": "wrong"})
    assert r.status_code == 401

def test_protected_route():
    client.post("/auth/register", json=USER)
    tokens = client.post("/auth/login", data={"username": USER["username"], "password": USER["password"]}).json()
    r = client.get("/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    assert r.json()["username"] == USER["username"]

def test_protected_no_token():
    r = client.get("/users/me")
    assert r.status_code == 401

def test_refresh_token():
    client.post("/auth/register", json=USER)
    tokens = client.post("/auth/login", data={"username": USER["username"], "password": USER["password"]}).json()
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    new_tokens = r.json()
    assert new_tokens["access_token"] != tokens["access_token"]

def test_refresh_token_rotation():
    """Old refresh token must be invalid after rotation."""
    client.post("/auth/register", json=USER)
    tokens = client.post("/auth/login", data={"username": USER["username"], "password": USER["password"]}).json()
    client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    # Try using old refresh token again → should fail
    r = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401

def test_logout():
    client.post("/auth/register", json=USER)
    tokens = client.post("/auth/login", data={"username": USER["username"], "password": USER["password"]}).json()
    r = client.post("/auth/logout", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    # Revoked token must not work
    r2 = client.get("/users/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r2.status_code == 401

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

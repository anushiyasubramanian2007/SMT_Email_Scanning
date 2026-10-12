import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure backend directory is in python path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app

FIXTURES_DIR = os.path.join(BACKEND_DIR, "tests", "fixtures")
TEST_API_KEY = "pg-forensic-secret-key-change-me-in-production"

@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)

@pytest.fixture
def auth_headers():
    """Standard authenticated headers for forensic endpoints."""
    return {"X-API-Key": TEST_API_KEY}

@pytest.fixture
def load_fixture():
    """Helper fixture to read .eml sample fixtures."""
    def _loader(filename: str) -> bytes:
        filepath = os.path.join(FIXTURES_DIR, filename)
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Fixture not found at {filepath}")
        with open(filepath, "rb") as f:
            return f.read()
    return _loader

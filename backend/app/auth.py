import os
from typing import Optional
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader, HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv

load_dotenv()

# Header-based API key: X-API-Key: <key>
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# Bearer token header: Authorization: Bearer <key>
bearer_auth = HTTPBearer(auto_error=False)

def get_forensic_api_key() -> str:
    """Retrieve the expected forensic API key from environment."""
    return os.getenv("FORENSIC_API_KEY", "pg-forensic-secret-key-change-me-in-production").strip()

def verify_forensic_api_key(
    header_key: Optional[str] = Security(api_key_header),
    bearer_creds: Optional[HTTPAuthorizationCredentials] = Security(bearer_auth)
) -> str:
    """
    Validates API-key authentication for sensitive forensic endpoints.
    Accepts key via 'X-API-Key' header or 'Authorization: Bearer <token>'.
    """
    expected_key = get_forensic_api_key()
    
    # 1. Check X-API-Key header
    if header_key and header_key.strip() == expected_key:
        return header_key.strip()
        
    # 2. Check Bearer token
    if bearer_creds and bearer_creds.credentials and bearer_creds.credentials.strip() == expected_key:
        return bearer_creds.credentials.strip()

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Missing or invalid forensic API key. Provide a valid 'X-API-Key' or 'Authorization: Bearer <token>' header.",
        headers={"WWW-Authenticate": "Bearer"},
    )

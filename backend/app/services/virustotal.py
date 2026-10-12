import os
import requests
import base64
from typing import Optional, Dict, Any

def check_url_virustotal(url: str) -> Optional[Dict[str, Any]]:
    """
    Checks a URL against the VirusTotal v3 API.
    Returns a dict with 'malicious_count' and 'total_count', or None if disabled/error.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if not api_key or api_key == "your_virustotal_key_here":
        return None # Silently disable if no key is provided
        
    print(f"🔍 Checking VirusTotal for URL: {url}")
    
    # VirusTotal v3 URL API uses URL-safe base64 encoded URLs without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(api_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        elif response.status_code == 404:
            # URL not found in VT database, this is fine.
            return {"malicious": 0, "suspicious": 0, "harmless": 0}
        else:
            print(f"⚠️ VirusTotal API error: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"⚠️ VirusTotal Request Failed: {e}")
        return None

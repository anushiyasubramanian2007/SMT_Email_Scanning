from pydantic import BaseModel
from typing import List, Optional, Union

class EmailAnalysisRequest(BaseModel):
    subject: str
    body: str
    sender_email: str
    sender_name: str
    links: List[str]
    attachments: Optional[List[str]] = []
    is_authenticated: Optional[bool] = True

class Indicator(BaseModel):
    type: str
    description: str

class AttachmentResult(BaseModel):
    filename: str
    status: str  # "safe" (legitimate), "phishing", "suspicious"
    threat_type: Optional[str] = None
    details: Optional[str] = None

class EmailAnalysisResponse(BaseModel):
    verdict: str  # "legitimate" / "safe", "suspicious", "phishing", "inconclusive"
    display_verdict: Optional[str] = None  # "LEGITIMATE", "PHISHING", "SUSPICIOUS"
    risk_category: str
    indicators: List[Indicator]
    attachments_analyzed: Optional[List[AttachmentResult]] = []
    explanation: str
    recommended_action: str

class UrlAnalysisRequest(BaseModel):
    url: str

class UrlAnalysisResponse(BaseModel):
    verdict: str
    indicators: List[Indicator]

class AttachmentAnalysisResponse(BaseModel):
    filename: str
    verdict: str  # "legitimate" / "safe", "suspicious", "phishing"
    sha256: Optional[str] = None
    detected_type: Optional[str] = None
    indicators: List[Indicator]
    explanation: str
    recommended_action: Optional[str] = None

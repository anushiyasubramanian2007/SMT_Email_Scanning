from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class ForensicFinding(BaseModel):
    id: str = Field(..., description="Unique machine-readable identifier for the finding")
    severity: str = Field(..., description="INFO, LOW, MEDIUM, HIGH, or CRITICAL")
    category: str = Field(..., description="Finding category: IDENTITY_SPOOFING, AUTHENTICATION, TRANSPORT, PROTOCOL, LURE, INFRASTRUCTURE")
    title: str = Field(..., description="Short descriptive title of the finding")
    description: str = Field(..., description="Plain-English explanation of why this is suspicious or relevant")
    technical_detail: Optional[str] = Field(None, description="In-depth forensic evidence details")
    recommendation: Optional[str] = Field(None, description="Security analyst action or recommendation")

    @property
    def details(self) -> str:
        return f"{self.technical_detail or ''} {self.description or ''}".strip()

class RelayHop(BaseModel):
    hop_number: int = Field(..., description="Chronological hop sequence (1 = earliest origin hop, N = destination)")
    from_host: Optional[str] = None
    from_ip: Optional[str] = None
    by_host: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: Optional[str] = None
    delay_seconds: Optional[float] = None
    delay_flag: Optional[str] = None
    is_private_ip: bool = False
    country: Optional[str] = None
    city: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    hop_role: Optional[str] = None
    is_provider_relay: bool = False
    provider_name: Optional[str] = None
    raw: str

class AuthStatus(BaseModel):
    verdict: str = Field(..., description="pass, fail, softfail, neutral, none, permerror, temperror")
    details: Optional[str] = None
    domain: Optional[str] = None
    selector: Optional[str] = None
    aligned: Optional[bool] = None

class EmailEnvelope(BaseModel):
    from_header: Optional[str] = None
    from_address: Optional[str] = None
    from_display_name: Optional[str] = None
    from_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None
    reply_to: Optional[str] = None
    reply_to_domain: Optional[str] = None
    sender: Optional[str] = None
    to: List[str] = []
    cc: List[str] = []
    bcc: List[str] = []
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    message_id_domain: Optional[str] = None
    x_originating_ip: Optional[str] = None
    x_sender_ip: Optional[str] = None
    spf_client_ip: Optional[str] = None
    user_agent: Optional[str] = None

    @property
    def from_name(self) -> Optional[str]:
        return self.from_display_name

    @property
    def to_address(self) -> Optional[str]:
        return self.to[0] if self.to else None

class AuthenticationForensics(BaseModel):
    spf: AuthStatus
    dkim: AuthStatus
    dmarc: AuthStatus
    arc: Optional[Dict[str, Any]] = None
    raw_auth_results: List[str] = []
    raw_dkim_signatures: List[str] = []

class GeoIPIntel(BaseModel):
    ip: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    is_tor: bool = False
    is_vpn_proxy: bool = False
    is_cloud: bool = False
    threat_labels: List[str] = []

class OriginTraceResult(BaseModel):
    origin_status: str = Field(..., description="ORIGIN_FOUND, PROVIDER_RELAY, or ANONYMIZED")
    status_message: str = Field(..., description="Contextual message explaining origin status")
    provider_name: Optional[str] = None
    confidence_level: str = Field("LOW", description="LOW, MEDIUM, or HIGH")
    origin_ip: Optional[str] = None
    reliability_score: float = Field(..., ge=0.0, le=1.0, description="Confidence in this IP being the true originator")
    reliability_justification: str
    hop_number: Optional[int] = None
    hop_mta: Optional[str] = None
    geolocation: Optional[GeoIPIntel] = None
    location_unreliable: bool = False

class DomainIntelResult(BaseModel):
    domain: str
    base_domain: str
    creation_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    is_newly_registered: bool = False
    mx_records: List[str] = []
    has_mx: bool = False
    spf_record: Optional[str] = None
    has_spf: bool = False
    dmarc_record: Optional[str] = None
    has_dmarc: bool = False
    is_lookalike: bool = False
    lookalike_target: Optional[str] = None
    lookalike_technique: Optional[str] = None
    similarity_score: Optional[float] = None

class FactorScore(BaseModel):
    factor_name: str
    score: float
    weight: float
    max_score: float
    status: str  # "CLEAN", "WARNING", "CRITICAL"
    explanation: str

class FraudScoreBreakdown(BaseModel):
    overall_score: int = Field(..., ge=0, le=100)
    risk_tier: str  # LOW, MEDIUM, HIGH, CRITICAL
    predicted_category: str  # legitimate, suspicious, impersonation, phishing, bec_fraud
    primary_risk_driver: str
    nlp_linguistic_factor: FactorScore
    header_transport_factor: FactorScore
    authentication_factor: FactorScore
    domain_intel_factor: FactorScore
    ip_reputation_factor: FactorScore

class ForensicSummary(BaseModel):
    verdict: str = Field(..., description="LEGITIMATE, SUSPICIOUS, IMPERSONATION, PHISHING, or BEC_FRAUD")
    risk_score: int = Field(..., ge=0, le=100, description="0 (clean) to 100 (confirmed threat)")
    confidence: float = Field(..., ge=0.0, le=1.0)
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    executive_summary: str

class ForensicAnalysisRequest(BaseModel):
    raw_content: Optional[str] = Field(None, description="Pasted RFC 5322 raw email source or headers")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)

class OriginAttributionResult(BaseModel):
    archetype: str  # COMPROMISED_ACCOUNT, SPOOFED_IDENTITY, ANONYMIZED_INFRASTRUCTURE, UNAUTHENTICATED_RELAY, BENIGN_ORIGIN
    confidence: float = Field(..., ge=0.0, le=1.0)
    title: str
    explanation: str
    evidence: List[str]

class LinkInfrastructure(BaseModel):
    url: str
    domain: str
    resolved_ip: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_suspicious_hosting: bool = False
    suspicious_hosting_provider: Optional[str] = None
    final_url: Optional[str] = None
    is_shortener: bool = False
    redirect_hops: List[str] = []
    has_idn_homoglyph: bool = False
    is_raw_ip: bool = False
    has_at_symbol: bool = False

    @property
    def hosting_provider(self) -> Optional[str]:
        return self.suspicious_hosting_provider or self.isp

    @property
    def is_idn_homoglyph(self) -> bool:
        return self.has_idn_homoglyph

    @property
    def expanded_url(self) -> Optional[str]:
        return self.final_url

class MxInfrastructure(BaseModel):
    domain: str
    primary_mx: Optional[str] = None
    resolved_ip: Optional[str] = None
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    is_suspicious_hosting: bool = False
    suspicious_hosting_provider: Optional[str] = None

    @property
    def mx_host(self) -> Optional[str]:
        return self.primary_mx

    @property
    def hosting_provider(self) -> Optional[str]:
        return self.suspicious_hosting_provider or self.isp

class WhoisIntel(BaseModel):
    domain: str
    available: bool = True
    creation_date: Optional[str] = None
    domain_age_days: Optional[int] = None
    registrar: Optional[str] = None
    registrant_country: Optional[str] = None
    is_newly_registered: bool = False

class ReplyToInfrastructure(BaseModel):
    from_address: str
    reply_to_address: str
    from_domain: str
    reply_to_domain: str
    reply_to_mismatch: bool = False
    mx_infra: Optional[MxInfrastructure] = None
    whois_intel: Optional[WhoisIntel] = None

    @property
    def is_mismatch(self) -> bool:
        return self.reply_to_mismatch

    @property
    def hosting_provider(self) -> Optional[str]:
        return self.mx_infra.hosting_provider if self.mx_infra else None

    @property
    def resolved_ip(self) -> Optional[str]:
        return self.mx_infra.resolved_ip if self.mx_infra else None

class InfrastructureEvidence(BaseModel):
    links: List[LinkInfrastructure] = []
    mx_infra: Optional[MxInfrastructure] = None
    whois_intel: Optional[WhoisIntel] = None
    reply_to_infra: Optional[ReplyToInfrastructure] = None
    corroborating_signals: List[str] = []
    confidence_score: float = 0.0
    confidence_level: str = "LOW"
    notes: Optional[str] = None

    @property
    def link_infrastructure(self) -> List[LinkInfrastructure]:
        return self.links

    @property
    def mx_infrastructure(self) -> Optional[MxInfrastructure]:
        return self.mx_infra

    @property
    def reply_to_infrastructure(self) -> Optional[ReplyToInfrastructure]:
        return self.reply_to_infra

    @property
    def sender_mx(self) -> Optional[MxInfrastructure]:
        return self.mx_infra

    @property
    def sender_whois(self) -> Optional[WhoisIntel]:
        return self.whois_intel

    @property
    def reply_to(self) -> Optional[ReplyToInfrastructure]:
        return self.reply_to_infra

    @property
    def confidence_cap(self) -> float:
        return self.confidence_score

    @property
    def confidence_note(self) -> Optional[str]:
        return self.notes

    @property
    def has_suspicious_link_hosting(self) -> bool:
        return any(l.is_suspicious_hosting for l in self.links)

class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # case, email, ip, domain, sender, asn, geo, url, campaign, relay_hop, mta, provider
    risk: str  # CRITICAL, HIGH, MEDIUM, LOW, CLEAN
    score: Optional[int] = 0
    details: Dict[str, Any] = Field(default_factory=dict)

class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str  # INCLUDES, SENT_BY, ORIGIN_IP, HOSTED_ON, LOCATED_IN, OPERATED_BY, CONTAINS_LINK, DIVERTS_TO, RELAYED_TO, INVERTED_RELAY_TO, DELIVERED_TO, EXCHANGES_FOR, RESOLVES_TO, EXPANDS_TO, ATTRIBUTED_TO, CORRELATED_WITH
    weight: float = 1.0

class ThreatGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    stats: Dict[str, Any]

class ForensicAnalysisResponse(BaseModel):
    sha256: str = Field(..., description="SHA-256 evidence fingerprint of raw email")
    ingested_at: str
    summary: ForensicSummary
    fraud_score: Optional[FraudScoreBreakdown] = None
    attribution: Optional[OriginAttributionResult] = None
    envelope: EmailEnvelope
    authentication: AuthenticationForensics
    relay_path: List[RelayHop]
    origin_trace: Optional[OriginTraceResult] = None
    domain_intel: Optional[DomainIntelResult] = None
    infrastructure_evidence: Optional[InfrastructureEvidence] = None
    threat_graph: Optional[ThreatGraphResponse] = None
    findings: List[ForensicFinding]
    security_recommendations: List[str]

# =========================================================================
# Case Management & Threat Intelligence Graph Schemas
# =========================================================================

class CaseCreate(BaseModel):
    title: str
    severity: Optional[str] = "MEDIUM"
    description: Optional[str] = None
    tags: Optional[str] = None
    assigned_to: Optional[str] = "SOC Analyst"

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[str] = None
    assigned_to: Optional[str] = None

class CaseResponse(BaseModel):
    id: str
    title: str
    status: str
    severity: str
    description: Optional[str] = None
    tags: Optional[str] = None
    assigned_to: Optional[str] = None
    email_count: int = 0
    created_at: str
    updated_at: str

class ThreatIndicatorResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    threat_score: int
    reputation_tags: Optional[str] = None
    occurrence_count: int
    first_seen: str
    last_seen: str

class ThreatCampaignResponse(BaseModel):
    id: str
    name: str
    threat_actor_type: str
    primary_ioc: Optional[str] = None
    status: str
    severity: str
    incident_count: int
    first_observed: str
    last_observed: str
    summary: Optional[str] = None


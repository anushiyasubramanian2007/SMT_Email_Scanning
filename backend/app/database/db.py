from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.join(BASE_DIR, 'phishingguard.db')}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class IncidentLog(Base):
    __tablename__ = "incident_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    item_type = Column(String, index=True) # "EMAIL", "URL", "ATTACHMENT", "FORENSIC_EMAIL"
    target = Column(String) # sender email, or URL, or filename
    verdict = Column(String) # "safe", "suspicious", "phishing", "critical_fraud"
    risk_category = Column(String)
    action_taken = Column(String) # e.g., "Warning Displayed", "Navigation Blocked", "Forensic Scan"

class GeoIPCache(Base):
    __tablename__ = "geoip_cache"

    ip = Column(String, primary_key=True, index=True)
    country = Column(String, nullable=True)
    country_code = Column(String, nullable=True)
    region = Column(String, nullable=True)
    city = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    asn = Column(String, nullable=True)
    isp = Column(String, nullable=True)
    org = Column(String, nullable=True)
    is_tor = Column(Boolean, default=False)
    is_vpn_proxy = Column(Boolean, default=False)
    is_cloud = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class DomainIntelCache(Base):
    __tablename__ = "domain_intel_cache"

    domain = Column(String, primary_key=True, index=True)
    creation_date = Column(DateTime, nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    registrar = Column(String, nullable=True)
    is_nrd = Column(Boolean, default=False)
    mx_records = Column(Text, nullable=True) # JSON array of MX hosts
    spf_record = Column(Text, nullable=True)
    dmarc_record = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class IntelCache(Base):
    __tablename__ = "intel_cache"

    id = Column(Integer, primary_key=True, index=True)
    intel_type = Column(String, index=True)  # "LINK_INFRA", "MX_INFRA", "WHOIS_INTEL", "REPLY_TO_INFRA"
    cache_key = Column(String, index=True)
    data_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class Case(Base):
    __tablename__ = "cases"

    id = Column(String, primary_key=True, index=True) # e.g. "CASE-20260924-001"
    title = Column(String, nullable=False)
    status = Column(String, default="OPEN", index=True) # OPEN, INVESTIGATING, ESCALATED, CLOSED
    severity = Column(String, default="MEDIUM", index=True) # LOW, MEDIUM, HIGH, CRITICAL
    description = Column(Text, nullable=True)
    tags = Column(String, nullable=True) # comma-separated
    assigned_to = Column(String, default="SOC Analyst", nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class CaseEmail(Base):
    __tablename__ = "case_emails"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(String, index=True, nullable=True)
    message_id = Column(String, index=True, nullable=True)
    subject = Column(String, nullable=True)
    sender = Column(String, index=True, nullable=True)
    recipient = Column(String, nullable=True)
    threat_category = Column(String, index=True, default="legitimate")
    fraud_score = Column(Integer, default=0)
    risk_tier = Column(String, default="LOW")
    origin_ip = Column(String, nullable=True)
    origin_country = Column(String, nullable=True)
    campaign_id = Column(String, index=True, nullable=True)
    attribution_type = Column(String, nullable=True)
    raw_json = Column(Text, nullable=True) # Serialized full ForensicAnalysisResponse
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    ioc_type = Column(String, index=True) # ip, domain, sender, url, asn, hash
    value = Column(String, index=True)
    threat_score = Column(Integer, default=0)
    reputation_tags = Column(String, nullable=True)
    first_seen = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    occurrence_count = Column(Integer, default=1)
    notes = Column(Text, nullable=True)

class ThreatCampaign(Base):
    __tablename__ = "threat_campaigns"

    id = Column(String, primary_key=True, index=True) # e.g. "CAMP-BEC-001"
    name = Column(String, nullable=False)
    threat_actor_type = Column(String, default="Unknown Threat Actor")
    primary_ioc = Column(String, nullable=True)
    status = Column(String, default="ACTIVE")
    severity = Column(String, default="HIGH")
    first_observed = Column(DateTime, default=datetime.datetime.utcnow)
    last_observed = Column(DateTime, default=datetime.datetime.utcnow)
    incident_count = Column(Integer, default=1)
    summary = Column(Text, nullable=True)

class EmailIndicatorAssociation(Base):
    __tablename__ = "email_indicator_associations"

    id = Column(Integer, primary_key=True, index=True)
    case_email_id = Column(Integer, index=True)
    indicator_id = Column(Integer, index=True)
    relationship = Column(String) # SENT_FROM, ORIGIN_IP_OF, CONTAINS_URL, ATTACHED_TO, FROM_DOMAIN_OF

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


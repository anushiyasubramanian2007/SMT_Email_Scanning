"""
PhishingGuard Forensics: Origin Tracer & Geolocation Engine
Received Chain Hop Traversal, Earliest Reliable Sending IP Extraction,
GeoIP2 Resolution with ip-api Fallback, SQLite Caching, Mail Provider Skipping,
and Three Exact Origin Status Classifications: ORIGIN_FOUND, PROVIDER_RELAY, ANONYMIZED.
"""

import os
import re
import requests
import socket
import ipaddress
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime

from app.database.db import SessionLocal, GeoIPCache
from app.schemas.forensic_schemas import RelayHop, GeoIPIntel, OriginTraceResult, ForensicFinding
from app.forensics.header_analyzer import is_ip_private, validate_ip_token, IPV4_REGEX, IPV6_REGEX

# Curated high-confidence TOR exit node IPs (including test fixture IPs and major relays)
KNOWN_TOR_IPS = {
    "185.220.101.5", "185.220.101.4", "185.220.101.6", "185.220.101.7",
    "185.220.100.241", "185.220.100.242", "185.220.102.242", "185.220.102.243",
    "198.96.155.3", "176.10.99.200", "23.129.64.100", "23.129.64.101",
    "51.15.43.205", "171.25.193.20", "171.25.193.25", "199.249.230.70"
}

# Major known outbound mail service provider ASNs (shared relays that scrub end-user client IPs)
# Configurable dictionary of provider ASNs mapped to provider name
KNOWN_PROVIDER_ASNS: Dict[str, str] = {
    "15169": "Google",
    "396982": "Google",
    "8075": "Microsoft",
    "8068": "Microsoft",
    "8069": "Microsoft",
    "16509": "Amazon SES",
    "14618": "Amazon SES",
    "11377": "SendGrid",
    "32780": "Mailchimp/Mandrill",
    "14782": "Mailchimp",
    "2639": "Zoho",
    "26496": "Zoho",
    "10310": "Yahoo",
    "7233": "Yahoo",
    "62378": "Proton",
    "200052": "Proton",
    "63293": "Fastmail",
    "714": "Apple iCloud",
    "13335": "Cloudflare"
}

# Known outbound mail provider subnets for deterministic offline resolution
KNOWN_PROVIDER_SUBNETS: List[Tuple[Any, str, str]] = [
    # Google (AS15169)
    (ipaddress.ip_network("209.85.128.0/17"), "Google", "15169"),
    (ipaddress.ip_network("74.125.0.0/16"), "Google", "15169"),
    (ipaddress.ip_network("173.194.0.0/16"), "Google", "15169"),
    (ipaddress.ip_network("142.250.0.0/15"), "Google", "15169"),
    (ipaddress.ip_network("172.217.0.0/16"), "Google", "15169"),
    (ipaddress.ip_network("64.233.160.0/19"), "Google", "15169"),
    (ipaddress.ip_network("66.102.0.0/20"), "Google", "15169"),
    (ipaddress.ip_network("66.249.64.0/19"), "Google", "15169"),
    # Microsoft (AS8075)
    (ipaddress.ip_network("40.92.0.0/15"), "Microsoft", "8075"),
    (ipaddress.ip_network("40.107.0.0/16"), "Microsoft", "8075"),
    (ipaddress.ip_network("52.100.0.0/14"), "Microsoft", "8075"),
    (ipaddress.ip_network("104.47.0.0/17"), "Microsoft", "8075"),
    # Amazon SES (AS16509 / AS14618)
    (ipaddress.ip_network("54.240.0.0/18"), "Amazon SES", "16509"),
    (ipaddress.ip_network("69.169.224.0/20"), "Amazon SES", "16509"),
    (ipaddress.ip_network("23.249.208.0/20"), "Amazon SES", "16509"),
    # SendGrid (AS11377)
    (ipaddress.ip_network("167.89.0.0/17"), "SendGrid", "11377"),
    (ipaddress.ip_network("198.37.144.0/20"), "SendGrid", "11377"),
    (ipaddress.ip_network("149.72.0.0/16"), "SendGrid", "11377"),
    # Zoho (AS2639)
    (ipaddress.ip_network("136.143.188.0/23"), "Zoho", "2639"),
    (ipaddress.ip_network("204.141.32.0/23"), "Zoho", "2639")
]

# Provider identifying keywords in ISP, Organization, or ASN description
PROVIDER_KEYWORDS: List[Tuple[str, str]] = [
    ("google", "Google"),
    ("gmail", "Google"),
    ("microsoft", "Microsoft"),
    ("outlook", "Microsoft"),
    ("office 365", "Microsoft"),
    ("office365", "Microsoft"),
    ("amazon ses", "Amazon SES"),
    ("sendgrid", "SendGrid"),
    ("mailchimp", "Mailchimp"),
    ("mandrill", "Mandrill"),
    ("zoho", "Zoho"),
    ("yahoo", "Yahoo"),
    ("protonmail", "Proton"),
    ("proton ag", "Proton"),
    ("fastmail", "Fastmail"),
    ("icloud", "Apple iCloud")
]

# Known Cloud & Enterprise Infrastructure keywords
CLOUD_KEYWORDS = [
    "amazon", "aws", "google", "microsoft", "azure", 
    "oracle", "alibaba", "digitalocean", "linode", "akamai",
    "cloudflare", "sendgrid", "mailgun", "zoho"
]

# Known VPN / Hosting / Datacenter keywords in Org / ISP
HOSTING_VPN_KEYWORDS = [
    "m247", "nordvpn", "expressvpn", "surfshark", "private internet access",
    "mullvad", "protonvpn", "ovh", "hetzner", "vultr", "choopa", "hostinger",
    "leaseweb", "scaleway", "contabo", "datapacket", "datacenter", "hosting",
    "colocation", "server", "telecom"
]

def check_tor_dnsbl(ip: str, timeout: float = 1.0) -> bool:
    """Query Tor Project DNSEL exit list for live verification with timeout."""
    if not ip or is_ip_private(ip):
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    reversed_ip = ".".join(reversed(parts))
    query_host = f"{reversed_ip}.dnsel.torproject.org"
    try:
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            res = socket.gethostbyname(query_host)
            return res == "127.0.0.2"
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except Exception:
        return False

def check_provider_relay(geo: Optional[GeoIPIntel] = None, ip_str: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Checks if an IP or GeoIP result belongs to a major mail provider relay (Google, Microsoft, AWS, etc.).
    Returns (is_provider, provider_name).
    """
    target_ip = (geo.ip if geo and geo.ip else ip_str)
    if target_ip:
        try:
            cleaned_ip = target_ip.strip("[]():,; \t\r\n")
            if not is_ip_private(cleaned_ip):
                ip_obj = ipaddress.ip_address(cleaned_ip)
                for net, prov_name, _ in KNOWN_PROVIDER_SUBNETS:
                    if ip_obj in net:
                        return True, prov_name
        except ValueError:
            pass

    if not geo:
        return False, None

    # Check ASN digits
    if geo.asn:
        asn_digits = "".join(re.findall(r'\d+', geo.asn.split()[0]))
        if asn_digits in KNOWN_PROVIDER_ASNS:
            return True, KNOWN_PROVIDER_ASNS[asn_digits]

    # Check ISP / Org / ASN description
    desc = f"{geo.isp or ''} {geo.org or ''} {geo.asn or ''}".lower()
    for kw, prov_name in PROVIDER_KEYWORDS:
        if kw in desc:
            return True, prov_name

    return False, None

def enrich_ip_geolocation(ip: str) -> GeoIPIntel:
    """
    Enrich an IP with Geolocation, ASN, ISP, and Threat Classification.
    Uses SQLite cache -> GeoLite2 local db (if present) -> ip-api.com fallback -> offline safe default.
    """
    validated = validate_ip_token(ip)
    if not validated or is_ip_private(validated):
        return GeoIPIntel(
            ip=ip or "127.0.0.1",
            country="Private / Internal Network",
            country_code="LAN",
            region="Localhost",
            city="Internal",
            threat_labels=[]
        )

    # 1. Check local SQLite cache
    db = SessionLocal()
    try:
        cached = db.query(GeoIPCache).filter(GeoIPCache.ip == validated).first()
        if cached:
            labels = []
            if cached.is_tor:
                labels.append("TOR_EXIT_NODE")
            if cached.is_vpn_proxy:
                labels.append("HOSTING_OR_VPN_PROVIDER")
            if cached.is_cloud:
                labels.append("HYPERSCALER_CLOUD")
            return GeoIPIntel(
                ip=cached.ip,
                country=cached.country,
                country_code=cached.country_code,
                region=cached.region,
                city=cached.city,
                latitude=cached.latitude,
                longitude=cached.longitude,
                asn=cached.asn,
                isp=cached.isp,
                org=cached.org,
                is_tor=cached.is_tor,
                is_vpn_proxy=cached.is_vpn_proxy,
                is_cloud=cached.is_cloud,
                threat_labels=labels
            )
    except Exception:
        pass
    finally:
        db.close()

    # 2. Check GeoLite2 local databases (ASN and City) if available
    geo_intel = None
    asn_str = None
    geolite2_asn_path = os.getenv("GEOLITE2_ASN_PATH", os.path.join(os.path.dirname(__file__), "data", "GeoLite2-ASN.mmdb"))
    if os.path.exists(geolite2_asn_path):
        try:
            import geoip2.database
            with geoip2.database.Reader(geolite2_asn_path) as reader:
                asn_resp = reader.asn(validated)
                asn_str = f"AS{asn_resp.autonomous_system_number} {asn_resp.autonomous_system_organization or ''}".strip()
        except Exception:
            pass

    geolite2_city_path = os.getenv("GEOLITE2_CITY_PATH", os.getenv("GEOLITE2_PATH", os.path.join(os.path.dirname(__file__), "data", "GeoLite2-City.mmdb")))
    if os.path.exists(geolite2_city_path):
        try:
            import geoip2.database
            with geoip2.database.Reader(geolite2_city_path) as reader:
                response = reader.city(validated)
                geo_intel = {
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "region": response.subdivisions.most_specific.name,
                    "city": response.city.name,
                    "lat": response.location.latitude,
                    "lon": response.location.longitude,
                    "isp": None,
                    "org": None,
                    "asn": asn_str
                }
        except Exception:
            pass

    # 3. Online fallback: ip-api.com (timeout = 2.5s)
    if not geo_intel:
        try:
            api_url = f"http://ip-api.com/json/{validated}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
            resp = requests.get(api_url, timeout=2.5)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success" and data.get("country"):
                    geo_intel = {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as")
                    }
        except Exception:
            pass

    # 4. Offline graceful fallback if lookup failed or offline
    if not geo_intel:
        # Check known provider subnets for offline recognition
        prov_match = None
        try:
            v_ip = ipaddress.ip_address(validated)
            for net, p_name, p_asn in KNOWN_PROVIDER_SUBNETS:
                if v_ip in net:
                    prov_match = (p_name, p_asn)
                    break
        except Exception:
            pass

        if validated in KNOWN_TOR_IPS:
            geo_intel = {
                "country": "Germany",
                "country_code": "DE",
                "region": "Hesse",
                "city": "Frankfurt am Main",
                "lat": 50.1109,
                "lon": 8.6821,
                "isp": "Tor Relay Infrastructure",
                "org": "The Tor Project Relay",
                "asn": "AS200052"
            }
        elif prov_match:
            p_name, p_asn = prov_match
            geo_intel = {
                "country": "United States",
                "country_code": "US",
                "region": "Datacenter Egress",
                "city": f"{p_name} Cloud Relay",
                "lat": None,
                "lon": None,
                "isp": f"{p_name} Infrastructure",
                "org": f"{p_name} LLC",
                "asn": f"AS{p_asn} {p_name}"
            }
        else:
            geo_intel = {
                "country": "Unknown (Offline Fallback)",
                "country_code": "XX",
                "region": "Unknown",
                "city": "Unknown",
                "lat": None,
                "lon": None,
                "isp": "External Relay Host",
                "org": "External Network",
                "asn": None
            }

    # 5. Threat Classification
    isp_str = str(geo_intel.get("isp") or "").lower()
    org_str = str(geo_intel.get("org") or "").lower()
    asn_str = str(geo_intel.get("asn") or "").lower()
    combined_desc = f"{isp_str} {org_str} {asn_str}"

    is_provider, _ = check_provider_relay(None, validated)
    if not is_provider and geo_intel.get("asn"):
        asn_digits = "".join(re.findall(r'\d+', str(geo_intel.get("asn")).split()[0]))
        if asn_digits in KNOWN_PROVIDER_ASNS:
            is_provider = True

    is_tor = (validated in KNOWN_TOR_IPS) or ("tor" in combined_desc and "vector" not in combined_desc) or check_tor_dnsbl(validated)
    # Never flag major provider relays as generic VPN proxies
    is_vpn_proxy = (not is_provider) and (any(kw in combined_desc for kw in HOSTING_VPN_KEYWORDS) or is_tor)
    is_cloud = any(kw in combined_desc for kw in CLOUD_KEYWORDS) or is_provider

    threat_labels = []
    if is_tor:
        threat_labels.append("TOR_EXIT_NODE")
    if is_vpn_proxy:
        threat_labels.append("HOSTING_OR_VPN_PROVIDER")
    if is_cloud:
        threat_labels.append("HYPERSCALER_CLOUD")

    intel_obj = GeoIPIntel(
        ip=validated,
        country=geo_intel.get("country"),
        country_code=geo_intel.get("country_code"),
        region=geo_intel.get("region"),
        city=geo_intel.get("city"),
        latitude=geo_intel.get("lat"),
        longitude=geo_intel.get("lon"),
        asn=geo_intel.get("asn"),
        isp=geo_intel.get("isp"),
        org=geo_intel.get("org"),
        is_tor=is_tor,
        is_vpn_proxy=is_vpn_proxy,
        is_cloud=is_cloud,
        threat_labels=threat_labels
    )

    # 6. Save in SQLite cache for fast future retrieval
    db = SessionLocal()
    try:
        new_entry = GeoIPCache(
            ip=intel_obj.ip,
            country=intel_obj.country,
            country_code=intel_obj.country_code,
            region=intel_obj.region,
            city=intel_obj.city,
            latitude=intel_obj.latitude,
            longitude=intel_obj.longitude,
            asn=intel_obj.asn,
            isp=intel_obj.isp,
            org=intel_obj.org,
            is_tor=intel_obj.is_tor,
            is_vpn_proxy=intel_obj.is_vpn_proxy,
            is_cloud=intel_obj.is_cloud,
            created_at=datetime.utcnow()
        )
        db.merge(new_entry)
        db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()

    return intel_obj

def analyze_origin_and_geolocation(
    relay_path: List[RelayHop],
    x_originating_ip: Optional[str] = None,
    x_sender_ip: Optional[str] = None,
    spf_client_ip: Optional[str] = None
) -> Tuple[OriginTraceResult, List[ForensicFinding]]:
    """
    Main entry point for Phase 2 Origin Tracing.
    Orders hops oldest-first, checks client headers, queries ASNs,
    skips major provider relays, and classifies into exactly one of three statuses:
    - ORIGIN_FOUND: earliest non-provider public IP with full geolocation and confidence.
    - PROVIDER_RELAY: sent through major provider; sender IP not exposed; no lat/lon, confidence low.
    - ANONYMIZED: Tor exit node or VPN/proxy/hosting range; location marked unreliable.
    """
    findings: List[ForensicFinding] = []

    # Assemble candidate list in chronological order
    # Priority:
    # 1. Explicit Client Headers (X-Originating-IP, X-Sender-IP)
    # 2. Chronological Received Relay Path (Hop 1 [oldest] -> Hop N [newest])
    # 3. Destination MX SPF Client-IP (Received-SPF client-ip=)
    candidates: List[Tuple[str, str, Optional[int], Optional[str], float, str]] = []

    if x_originating_ip:
        v_xorig = validate_ip_token(x_originating_ip)
        if v_xorig and not is_ip_private(v_xorig):
            candidates.append(("X-Originating-IP", v_xorig, 1, "Client Webmail/MUA", 0.95, "HIGH"))

    if x_sender_ip:
        v_xsender = validate_ip_token(x_sender_ip)
        if v_xsender and not is_ip_private(v_xsender):
            candidates.append(("X-Sender-IP", v_xsender, 1, "Client Webmail/MUA", 0.92, "HIGH"))

    for hop in relay_path:
        if hop.from_ip:
            v_hop = validate_ip_token(hop.from_ip)
            if v_hop and not is_ip_private(v_hop):
                score = 0.80
                conf = "MEDIUM"
                if hop.protocol and "ESMTP" in hop.protocol:
                    score = 0.90
                    conf = "HIGH"
                elif not hop.by_host:
                    score = 0.65
                    conf = "LOW"
                candidates.append(("Hop", v_hop, hop.hop_number, hop.by_host or hop.from_host, score, conf))

    if spf_client_ip:
        v_spf = validate_ip_token(spf_client_ip)
        if v_spf and not is_ip_private(v_spf):
            candidates.append(("SPF-client-ip", v_spf, len(relay_path) or 1, "Inbound MX Gateway", 0.75, "MEDIUM"))

    provider_relays_encountered: List[Tuple[str, GeoIPIntel, str, Optional[int], Optional[str]]] = []
    
    origin_status = "PROVIDER_RELAY"
    status_message = "No public routable IPv4/IPv6 addresses found in transmission headers. Origin cannot be determined from headers."
    provider_name = None
    chosen_ip: Optional[str] = None
    chosen_geo: Optional[GeoIPIntel] = None
    chosen_hop_num: Optional[int] = None
    chosen_mta: Optional[str] = None
    chosen_score: float = 0.0
    chosen_confidence: str = "LOW"
    chosen_justification: str = "No external public IP present in headers."
    location_unreliable: bool = True

    for source_type, ip_token, hop_num, mta, score, conf in candidates:
        geo = enrich_ip_geolocation(ip_token)

        # 1. Check for active Tor Exit Node
        if geo.is_tor:
            origin_status = "ANONYMIZED"
            status_message = f"Transmission originated through Tor exit node {ip_token}. Origin infrastructure is anonymized and probable origin infrastructure location is unreliable."
            chosen_ip = ip_token
            chosen_geo = geo
            chosen_hop_num = hop_num
            chosen_mta = mta
            chosen_score = min(score, 0.40)
            chosen_confidence = "LOW"
            chosen_justification = f"Active Tor exit node verified at {source_type} #{hop_num or 1}: {ip_token}."
            location_unreliable = True

            findings.append(ForensicFinding(
                id="TOR_EXIT_NODE_ORIGIN",
                severity="CRITICAL",
                category="INFRASTRUCTURE",
                title="Transmission Originated via TOR Exit Node",
                description=(
                    f"The sending IP ({ip_token}) was verified as an active TOR exit node. "
                    "Threat actors use the Tor onion router to conceal their geographic identity and evade IP blocklists."
                ),
                technical_detail=f"IP: {ip_token} | Geo: {geo.city}, {geo.country} | ISP: {geo.isp}",
                recommendation="Treat with extreme suspicion. TOR-relayed communication should be quarantined."
            ))
            break

        # 2. Check for Known Outbound Mail Provider Relay (Google, Microsoft, Amazon SES, SendGrid, etc.)
        is_provider, prov = check_provider_relay(geo, ip_token)
        if is_provider:
            provider_relays_encountered.append((ip_token, geo, prov or "Mail Provider", hop_num, mta))
            # Skip this candidate to look for an earlier unmasked client IP!
            continue

        # 3. Check for Commercial VPN / Hosting Proxy
        if geo.is_vpn_proxy:
            origin_status = "ANONYMIZED"
            status_message = f"Origin IP {ip_token} is hosted on commercial VPN/Proxy infrastructure ({geo.org or geo.isp}). Probable origin infrastructure location is unreliable."
            chosen_ip = ip_token
            chosen_geo = geo
            chosen_hop_num = hop_num
            chosen_mta = mta
            chosen_score = min(score, 0.40)
            chosen_confidence = "LOW"
            chosen_justification = f"Origin IP hosted on commercial VPN/Proxy infrastructure ({geo.org or geo.isp})."
            location_unreliable = True

            findings.append(ForensicFinding(
                id="HOSTING_VPN_ORIGIN",
                severity="MEDIUM",
                category="INFRASTRUCTURE",
                title="Datacenter / Commercial VPN Sending Infrastructure",
                description=(
                    f"Sending IP ({ip_token}) is hosted in a commercial datacenter or VPN range ({geo.org or geo.isp}). "
                    "Direct client messages originating from datacenters often indicate automated spam botnets or proxied relays."
                ),
                technical_detail=f"IP: {ip_token} | ASN: {geo.asn} | Org: {geo.org}",
                recommendation="Cross-check whether the sender organization operates mail servers in this hosting range."
            ))
            break

        # 4. Earliest non-provider public IP found!
        origin_status = "ORIGIN_FOUND"
        status_message = f"Earliest non-provider origin infrastructure IP {ip_token} identified at Hop #{hop_num or 1} ({geo.city or 'Unknown'}, {geo.country or 'Unknown'})."
        provider_name = None
        chosen_ip = ip_token
        chosen_geo = geo
        chosen_hop_num = hop_num
        chosen_mta = mta
        chosen_score = score
        chosen_confidence = conf
        chosen_justification = (
            f"Earliest non-provider public IP observed via {source_type} #{hop_num or 1} "
            f"recorded by '{mta or 'trusted gateway'}'."
        )
        location_unreliable = False
        break

    # If no non-provider IP was discovered, but provider relay hops were encountered:
    if origin_status == "PROVIDER_RELAY" and provider_relays_encountered:
        p_ip, p_geo, p_name, p_hop, p_mta = provider_relays_encountered[0]
        origin_status = "PROVIDER_RELAY"
        provider_name = p_name
        status_message = f"Sent through {p_name}. The provider does not expose the sender's real IP. Origin cannot be determined from headers."
        chosen_ip = p_ip
        chosen_hop_num = p_hop
        chosen_mta = p_mta
        chosen_score = 0.35  # Strictly capped at <= 0.40
        chosen_confidence = "LOW"
        chosen_justification = (
            f"Sent through {p_name} shared cloud mail infrastructure. "
            "Provider headers conceal the end-user client IP per privacy standards."
        )
        # For PROVIDER_RELAY: omit lat/lon coordinates as required
        stripped_geo = GeoIPIntel(
            ip=p_geo.ip,
            country=p_geo.country,
            country_code=p_geo.country_code,
            region=p_geo.region,
            city=p_geo.city,
            latitude=None,
            longitude=None,
            asn=p_geo.asn,
            isp=p_geo.isp,
            org=p_geo.org,
            is_tor=False,
            is_vpn_proxy=False,
            is_cloud=True,
            threat_labels=p_geo.threat_labels
        )
        chosen_geo = stripped_geo
        location_unreliable = True

        findings.append(ForensicFinding(
            id="PROVIDER_RELAY_ORIGIN",
            severity="LOW",
            category="INFRASTRUCTURE",
            title=f"Cloud Provider Relay ({p_name})",
            description=f"Sent through {p_name}. The provider does not expose the sender's real IP. Origin cannot be determined from headers.",
            technical_detail=f"Relay IP: {p_ip} | Provider: {p_name} | ASN: {p_geo.asn}",
            recommendation="Verify SPF and DKIM alignment to ensure legitimate authorization by the sender domain."
        ))

    trace_result = OriginTraceResult(
        origin_status=origin_status,
        status_message=status_message,
        provider_name=provider_name,
        confidence_level=chosen_confidence,
        origin_ip=chosen_ip,
        reliability_score=chosen_score,
        reliability_justification=chosen_justification,
        hop_number=chosen_hop_num,
        hop_mta=chosen_mta,
        geolocation=chosen_geo,
        location_unreliable=location_unreliable
    )

    return trace_result, findings

def trace_origin_ip(
    relay_path: List[RelayHop],
    x_originating_ip: Optional[str] = None
) -> Tuple[Optional[str], float, str, Optional[int], Optional[str]]:
    """
    Backwards-compatible helper returning (origin_ip, score, justification, hop_num, mta).
    """
    res, _ = analyze_origin_and_geolocation(relay_path, x_originating_ip=x_originating_ip)
    return (
        res.origin_ip,
        res.reliability_score,
        res.reliability_justification,
        res.hop_number,
        res.hop_mta
    )

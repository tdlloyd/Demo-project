"""Non-browser IP reputation checks using free/open APIs and DNSBL lookups."""

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field

import aiohttp

logger = logging.getLogger(__name__)

# ── DNS-based blackhole lists (DNSBLs) ──────────────────────────────────────
# These are free, publicly queryable blocklists. A positive lookup means the
# IP is listed (i.e. has poor reputation in that list's opinion).
DNSBL_ZONES = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "dul.dnsbl.sorbs.net",
    "dnsbl-1.uceprotect.net",
    "cbl.abuseat.org",
    "all.s5h.net",
    "dnsbl.dronebl.org",
]


@dataclass
class IPInfo:
    """Aggregated information about the current public IP."""
    ip: str = ""
    hostname: str = ""
    org: str = ""
    asn: str = ""
    country: str = ""
    city: str = ""
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_mobile: bool = False
    abuse_confidence: int = 0           # 0-100 from AbuseIPDB (if key provided)
    fraud_score: int = 0                # 0-100 from ipqualityscore (if key provided)
    dnsbl_listed: list = field(default_factory=list)
    dnsbl_total_checked: int = 0
    raw: dict = field(default_factory=dict)


# ── Public IP discovery ──────────────────────────────────────────────────────

async def get_public_ip(session: aiohttp.ClientSession) -> str:
    """Resolve the machine's outbound public IP via multiple fallback services."""
    services = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for url in services:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = (await resp.text()).strip()
                    # ipify returns JSON
                    if text.startswith("{"):
                        import json
                        return json.loads(text)["ip"]
                    return text
        except Exception:
            continue
    raise RuntimeError("Could not determine public IP from any service")


# ── DNSBL lookup ─────────────────────────────────────────────────────────────

def _reverse_ip(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


async def _query_dnsbl(ip: str, zone: str) -> bool:
    """Return True if the IP is listed in the given DNSBL zone."""
    query = f"{_reverse_ip(ip)}.{zone}"
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, socket.getaddrinfo, query, None)
        return True   # got an answer → listed
    except socket.gaierror:
        return False  # NXDOMAIN → not listed


async def check_dnsbls(ip: str) -> tuple[list[str], int]:
    """Check the IP against all DNSBL zones in parallel.
    Returns (listed_zones, total_checked).
    """
    # Skip non-IPv4 for DNSBL (most lists are v4 only)
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            logger.info("Skipping DNSBL checks for non-IPv4 address %s", ip)
            return [], 0
    except ValueError:
        return [], 0

    tasks = [_query_dnsbl(ip, zone) for zone in DNSBL_ZONES]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    listed = []
    checked = 0
    for zone, result in zip(DNSBL_ZONES, results):
        if isinstance(result, Exception):
            continue
        checked += 1
        if result:
            listed.append(zone)

    return listed, checked


# ── Free API enrichment ──────────────────────────────────────────────────────

async def _enrich_ipapi(session: aiohttp.ClientSession, ip: str, info: IPInfo):
    """Populate geo/org/ASN fields via ip-api.com (free, no key)."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,proxy,hosting,mobile,query"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            data = await resp.json(content_type=None)
            if data.get("status") == "success":
                info.country = data.get("country", "")
                info.city = data.get("city", "")
                info.org = data.get("org") or data.get("isp", "")
                info.asn = data.get("as", "")
                info.is_proxy = data.get("proxy", False)
                info.is_datacenter = data.get("hosting", False)
                info.is_mobile = data.get("mobile", False)
                info.raw["ip-api"] = data
    except Exception as exc:
        logger.debug("ip-api.com failed: %s", exc)


async def _enrich_ipinfo(session: aiohttp.ClientSession, ip: str, info: IPInfo):
    """Populate hostname, VPN hints via ipinfo.io (free tier, no key)."""
    url = f"https://ipinfo.io/{ip}/json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as resp:
            data = await resp.json(content_type=None)
            info.hostname = data.get("hostname", "")
            info.raw["ipinfo"] = data
            # ipinfo's free tier doesn't expose privacy fields, but the
            # hostname can hint at datacenter IPs (e.g. ec2-*.compute.amazonaws.com)
            host = info.hostname.lower()
            dc_hints = ["amazonaws.com", "googleusercontent.com", "azure.com",
                        "vultr.com", "linode.com", "digitalocean", "hetzner",
                        "ovh.", "scaleway"]
            if any(h in host for h in dc_hints):
                info.is_datacenter = True
    except Exception as exc:
        logger.debug("ipinfo.io failed: %s", exc)


async def _check_abuseipdb(session: aiohttp.ClientSession, ip: str, info: IPInfo, api_key: str):
    """Optional: query AbuseIPDB for abuse confidence score (needs free API key)."""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    try:
        async with session.get(url, headers=headers, params=params,
                               timeout=aiohttp.ClientTimeout(total=10)) as resp:
            data = await resp.json(content_type=None)
            abuse_data = data.get("data", {})
            info.abuse_confidence = abuse_data.get("abuseConfidenceScore", 0)
            info.is_tor = abuse_data.get("isTor", False)
            info.raw["abuseipdb"] = abuse_data
    except Exception as exc:
        logger.debug("AbuseIPDB failed: %s", exc)


async def _check_ipqs(session: aiohttp.ClientSession, ip: str, info: IPInfo, api_key: str):
    """Optional: query IPQualityScore for fraud score (needs free API key)."""
    url = f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}"
    params = {"strictness": 1, "allow_public_access_points": "true"}
    try:
        async with session.get(url, params=params,
                               timeout=aiohttp.ClientTimeout(total=10)) as resp:
            data = await resp.json(content_type=None)
            if data.get("success"):
                info.fraud_score = data.get("fraud_score", 0)
                info.is_vpn = info.is_vpn or data.get("vpn", False)
                info.is_tor = info.is_tor or data.get("tor", False)
                info.is_proxy = info.is_proxy or data.get("proxy", False)
                info.raw["ipqs"] = data
    except Exception as exc:
        logger.debug("IPQS failed: %s", exc)


# ── Main entry point ─────────────────────────────────────────────────────────

async def gather_ip_intelligence(
    abuseipdb_key: str | None = None,
    ipqs_key: str | None = None,
) -> IPInfo:
    """Run all non-browser IP reputation checks and return aggregated IPInfo."""
    info = IPInfo()

    async with aiohttp.ClientSession() as session:
        info.ip = await get_public_ip(session)
        logger.info("Public IP: %s", info.ip)

        # Run enrichment + DNSBL in parallel
        tasks = [
            _enrich_ipapi(session, info.ip, info),
            _enrich_ipinfo(session, info.ip, info),
        ]
        if abuseipdb_key:
            tasks.append(_check_abuseipdb(session, info.ip, info, abuseipdb_key))
        if ipqs_key:
            tasks.append(_check_ipqs(session, info.ip, info, ipqs_key))

        dnsbl_task = check_dnsbls(info.ip)
        tasks.append(dnsbl_task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # The last result is the DNSBL tuple
        dnsbl_result = results[-1]
        if isinstance(dnsbl_result, tuple):
            info.dnsbl_listed, info.dnsbl_total_checked = dnsbl_result

    return info

"""Combine captcha scan + IP intelligence into a single reputation score."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from ip_reputation.captcha_detector import SiteResult
from ip_reputation.ip_checks import IPInfo


@dataclass
class ReputationReport:
    """Final computed reputation output."""
    ip: str = ""
    overall_score: float = 0.0          # 0 (worst) – 100 (best)
    grade: str = ""                     # A+ … F
    captcha_rate: float = 0.0           # fraction of visits that hit a captcha
    block_rate: float = 0.0             # fraction of visits that were blocked
    captcha_scores: dict = field(default_factory=dict)   # per-provider breakdown
    ip_info: IPInfo | None = None
    component_scores: dict = field(default_factory=dict) # sub-scores for transparency

    # ── per-provider captcha stats ───────────────────────────────────────
    provider_stats: dict = field(default_factory=dict)


def _grade(score: float) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 55:
        return "D"
    return "F"


def compute_reputation(
    results: list[SiteResult],
    ip_info: IPInfo,
) -> ReputationReport:
    """
    Compute a 0-100 reputation score from captcha scan results and IP metadata.

    Scoring breakdown (weights):
        40%  Captcha encounter rate  (lower is better)
        20%  Block / hard-deny rate  (lower is better)
        15%  DNSBL listings          (fewer is better)
        10%  Proxy / VPN / Tor flags (not flagged is better)
        10%  Datacenter flag         (residential is better)
         5%  Abuse confidence score  (lower is better)
    """
    report = ReputationReport(ip=ip_info.ip, ip_info=ip_info)

    # ── Captcha encounter rate ───────────────────────────────────────────
    total_visits = len(results)
    if total_visits == 0:
        report.overall_score = 50.0
        report.grade = _grade(50)
        return report

    captcha_visits = sum(1 for r in results if r.captcha_detected)
    blocked_visits = sum(1 for r in results if r.blocked)

    report.captcha_rate = captcha_visits / total_visits
    report.block_rate = blocked_visits / total_visits

    # Per-provider stats
    provider_map: dict[str, dict] = {}
    for r in results:
        key = r.expected_provider
        if key not in provider_map:
            provider_map[key] = {"visits": 0, "captcha": 0, "blocked": 0}
        provider_map[key]["visits"] += 1
        if r.captcha_detected:
            provider_map[key]["captcha"] += 1
        if r.blocked:
            provider_map[key]["blocked"] += 1
    for provider, stats in provider_map.items():
        stats["captcha_rate"] = (
            stats["captcha"] / stats["visits"] if stats["visits"] else 0
        )
    report.provider_stats = provider_map

    # ── Component scores (each 0-100, higher is better) ──────────────────
    # 1. Captcha rate score
    captcha_score = max(0.0, 100.0 * (1 - report.captcha_rate))

    # 2. Block rate score
    block_score = max(0.0, 100.0 * (1 - report.block_rate * 2))  # penalise harder

    # 3. DNSBL score
    if ip_info.dnsbl_total_checked > 0:
        dnsbl_frac = len(ip_info.dnsbl_listed) / ip_info.dnsbl_total_checked
        dnsbl_score = max(0.0, 100.0 * (1 - dnsbl_frac * 3))  # 33%+ listed → 0
    else:
        dnsbl_score = 80.0  # unable to check; assume neutral-ish

    # 4. Proxy/VPN/Tor score
    proxy_penalty = 0
    if ip_info.is_proxy:
        proxy_penalty += 40
    if ip_info.is_vpn:
        proxy_penalty += 30
    if ip_info.is_tor:
        proxy_penalty += 50
    proxy_score = max(0.0, 100.0 - proxy_penalty)

    # 5. Datacenter score (residential IPs are typically more trusted)
    dc_score = 40.0 if ip_info.is_datacenter else 100.0

    # 6. AbuseIPDB confidence score (0 = clean, 100 = abusive)
    abuse_score = max(0.0, 100.0 - ip_info.abuse_confidence)

    report.component_scores = {
        "captcha_rate": round(captcha_score, 1),
        "block_rate": round(block_score, 1),
        "dnsbl": round(dnsbl_score, 1),
        "proxy_vpn_tor": round(proxy_score, 1),
        "datacenter": round(dc_score, 1),
        "abuse_confidence": round(abuse_score, 1),
    }

    # ── Weighted combination ─────────────────────────────────────────────
    overall = (
        0.40 * captcha_score
        + 0.20 * block_score
        + 0.15 * dnsbl_score
        + 0.10 * proxy_score
        + 0.10 * dc_score
        + 0.05 * abuse_score
    )
    report.overall_score = round(max(0.0, min(100.0, overall)), 1)
    report.grade = _grade(report.overall_score)

    return report


# ── Pretty-print ─────────────────────────────────────────────────────────────

def format_report(report: ReputationReport) -> str:
    """Render the reputation report as a human-readable string."""
    lines: list[str] = []
    w = 60

    lines.append("=" * w)
    lines.append("  IP REPUTATION REPORT")
    lines.append("=" * w)
    lines.append("")

    lines.append(f"  IP Address:      {report.ip}")
    if report.ip_info:
        lines.append(f"  Organization:    {report.ip_info.org}")
        lines.append(f"  ASN:             {report.ip_info.asn}")
        lines.append(f"  Location:        {report.ip_info.city}, {report.ip_info.country}")
        lines.append(f"  Hostname:        {report.ip_info.hostname or 'N/A'}")
        flags = []
        if report.ip_info.is_datacenter:
            flags.append("Datacenter")
        if report.ip_info.is_proxy:
            flags.append("Proxy")
        if report.ip_info.is_vpn:
            flags.append("VPN")
        if report.ip_info.is_tor:
            flags.append("Tor")
        if report.ip_info.is_mobile:
            flags.append("Mobile")
        lines.append(f"  Flags:           {', '.join(flags) if flags else 'None'}")

    lines.append("")
    lines.append("-" * w)
    lines.append("  OVERALL REPUTATION")
    lines.append("-" * w)
    lines.append("")

    bar_len = 30
    filled = round(report.overall_score / 100 * bar_len)
    bar = "█" * filled + "░" * (bar_len - filled)
    lines.append(f"  Score:  {report.overall_score:5.1f} / 100   [{bar}]  {report.grade}")
    lines.append("")

    lines.append("-" * w)
    lines.append("  COMPONENT SCORES")
    lines.append("-" * w)
    component_labels = {
        "captcha_rate": "Captcha Rate (40%)",
        "block_rate": "Block Rate (20%)",
        "dnsbl": "DNSBL Listings (15%)",
        "proxy_vpn_tor": "Proxy/VPN/Tor (10%)",
        "datacenter": "Datacenter (10%)",
        "abuse_confidence": "Abuse Score (5%)",
    }
    for key, label in component_labels.items():
        val = report.component_scores.get(key, 0)
        small_bar = "█" * round(val / 100 * 20) + "░" * (20 - round(val / 100 * 20))
        lines.append(f"  {label:<24s} {val:5.1f}  [{small_bar}]")
    lines.append("")

    # DNSBL detail
    if report.ip_info:
        lines.append("-" * w)
        lines.append("  DNSBL CHECK")
        lines.append("-" * w)
        lines.append(f"  Checked {report.ip_info.dnsbl_total_checked} blacklists, "
                      f"listed on {len(report.ip_info.dnsbl_listed)}")
        if report.ip_info.dnsbl_listed:
            for zone in report.ip_info.dnsbl_listed:
                lines.append(f"    ✗  {zone}")
        else:
            lines.append("    ✓  Not listed on any checked DNSBL")
        lines.append("")

    # Per-provider captcha stats
    lines.append("-" * w)
    lines.append("  CAPTCHA ENCOUNTER STATISTICS")
    lines.append("-" * w)
    lines.append(f"  {'Provider':<24s} {'Visits':>6s} {'Captcha':>8s} {'Rate':>8s}")
    lines.append(f"  {'-'*24} {'-'*6} {'-'*8} {'-'*8}")
    for provider, stats in sorted(report.provider_stats.items()):
        rate_str = f"{stats['captcha_rate']:.0%}"
        lines.append(
            f"  {provider:<24s} {stats['visits']:>6d} {stats['captcha']:>8d} {rate_str:>8s}"
        )
    lines.append("")
    lines.append(f"  Overall captcha rate:  {report.captcha_rate:.0%}")
    lines.append(f"  Overall block rate:    {report.block_rate:.0%}")
    lines.append("")
    lines.append("=" * w)

    # Interpretation
    lines.append("")
    if report.overall_score >= 90:
        lines.append("  ✓ Excellent reputation. This IP is unlikely to face")
        lines.append("    captchas or blocks on most websites.")
    elif report.overall_score >= 70:
        lines.append("  ~ Moderate reputation. This IP may occasionally see")
        lines.append("    captchas on aggressive anti-bot sites.")
    elif report.overall_score >= 50:
        lines.append("  ⚠ Below-average reputation. Expect frequent captchas")
        lines.append("    and possible soft blocks on protected sites.")
    else:
        lines.append("  ✗ Poor reputation. This IP is likely flagged by most")
        lines.append("    anti-bot systems. Consider changing IP or network.")
    lines.append("")

    return "\n".join(lines)

"""CLI entry point for the IP reputation scanner."""

import argparse
import asyncio
import json
import logging
import sys

from ip_reputation.captcha_detector import run_captcha_scan
from ip_reputation.ip_checks import gather_ip_intelligence
from ip_reputation.scoring import compute_reputation, format_report


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ip-reputation",
        description="Measure your IP's reputation by probing captcha-protected "
                    "sites and querying IP intelligence sources.",
    )
    p.add_argument(
        "-n", "--visits", type=int, default=3,
        help="Number of visits per site (default: 3)",
    )
    p.add_argument(
        "--headed", action="store_true",
        help="Run browser in headed (visible) mode",
    )
    p.add_argument(
        "--settle-delay", type=float, default=3.0,
        help="Seconds to wait after page load before scanning (default: 3.0)",
    )
    p.add_argument(
        "--abuseipdb-key", type=str, default=None,
        help="Optional AbuseIPDB API key for abuse confidence scoring",
    )
    p.add_argument(
        "--ipqs-key", type=str, default=None,
        help="Optional IPQualityScore API key for fraud scoring",
    )
    p.add_argument(
        "--json", dest="json_output", action="store_true",
        help="Output raw results as JSON instead of the formatted report",
    )
    p.add_argument(
        "--skip-browser", action="store_true",
        help="Skip Playwright browser scan (only run IP intelligence checks)",
    )
    p.add_argument(
        "--skip-ip-checks", action="store_true",
        help="Skip IP intelligence checks (only run browser captcha scan)",
    )
    p.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    p.add_argument(
        "--sites-file", type=str, default=None,
        help="JSON file with custom site list (array of {url, label, expected})",
    )
    return p.parse_args()


async def main() -> int:
    args = parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        datefmt="%H:%M:%S",
    )

    sites = None
    if args.sites_file:
        with open(args.sites_file) as f:
            sites = json.load(f)

    # ── Run IP intelligence checks ───────────────────────────────────────
    ip_info = None
    if not args.skip_ip_checks:
        logging.info("Running IP intelligence checks...")
        ip_info = await gather_ip_intelligence(
            abuseipdb_key=args.abuseipdb_key,
            ipqs_key=args.ipqs_key,
        )
        logging.info("IP: %s  (%s, %s)", ip_info.ip, ip_info.org, ip_info.country)
        if ip_info.dnsbl_listed:
            logging.warning("Listed on %d DNSBL(s): %s",
                            len(ip_info.dnsbl_listed), ip_info.dnsbl_listed)

    # ── Run browser captcha scan ─────────────────────────────────────────
    scan_results = []
    if not args.skip_browser:
        logging.info("Launching Firefox captcha scan (%d visits/site)...", args.visits)
        scan_results = await run_captcha_scan(
            sites=sites,
            visits_per_site=args.visits,
            headless=not args.headed,
            settle_delay=args.settle_delay,
        )
        captcha_count = sum(1 for r in scan_results if r.captcha_detected)
        logging.info("Scan complete: %d/%d visits triggered a captcha",
                     captcha_count, len(scan_results))

    # ── Need a minimal IPInfo if skipped ─────────────────────────────────
    if ip_info is None:
        from ip_reputation.ip_checks import IPInfo
        ip_info = IPInfo(ip="unknown")

    # ── Compute reputation ───────────────────────────────────────────────
    report = compute_reputation(scan_results, ip_info)

    # ── Output ───────────────────────────────────────────────────────────
    if args.json_output:
        output = {
            "ip": report.ip,
            "overall_score": report.overall_score,
            "grade": report.grade,
            "captcha_rate": report.captcha_rate,
            "block_rate": report.block_rate,
            "component_scores": report.component_scores,
            "provider_stats": report.provider_stats,
            "ip_info": {
                "org": ip_info.org,
                "asn": ip_info.asn,
                "country": ip_info.country,
                "city": ip_info.city,
                "is_vpn": ip_info.is_vpn,
                "is_proxy": ip_info.is_proxy,
                "is_tor": ip_info.is_tor,
                "is_datacenter": ip_info.is_datacenter,
                "dnsbl_listed": ip_info.dnsbl_listed,
                "dnsbl_total_checked": ip_info.dnsbl_total_checked,
                "abuse_confidence": ip_info.abuse_confidence,
                "fraud_score": ip_info.fraud_score,
            },
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_report(report))

    return 0


def entry():
    sys.exit(asyncio.run(main()))


if __name__ == "__main__":
    entry()

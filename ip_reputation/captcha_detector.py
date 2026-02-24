"""Playwright-based captcha detection across multiple captcha providers."""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from playwright.async_api import async_playwright, Page, BrowserContext

logger = logging.getLogger(__name__)

# CSS selectors and script signatures for each captcha provider.
CAPTCHA_SIGNATURES = {
    "reCAPTCHA_v2": {
        "iframes": ['iframe[src*="google.com/recaptcha"]', 'iframe[src*="recaptcha/api"]'],
        "elements": [".g-recaptcha", "#g-recaptcha", '[data-sitekey]'],
        "scripts": ["google.com/recaptcha", "gstatic.com/recaptcha"],
    },
    "reCAPTCHA_v3": {
        "iframes": [],
        "elements": [],
        "scripts": ["google.com/recaptcha/api.js?render="],
    },
    "hCaptcha": {
        "iframes": ['iframe[src*="hcaptcha.com"]', 'iframe[src*="assets.hcaptcha.com"]'],
        "elements": [".h-captcha", '[data-hcaptcha-sitekey]'],
        "scripts": ["hcaptcha.com/1/api.js", "js.hcaptcha.com"],
    },
    "FunCaptcha": {
        "iframes": ['iframe[src*="funcaptcha.com"]', 'iframe[src*="arkoselabs.com"]'],
        "elements": ["#FunCaptcha", "#arkose", '[data-fun-captcha]'],
        "scripts": ["funcaptcha.com/fc", "arkoselabs.com"],
    },
    "Cloudflare_Turnstile": {
        "iframes": ['iframe[src*="challenges.cloudflare.com"]'],
        "elements": [".cf-turnstile", '[data-turnstile-sitekey]'],
        "scripts": ["challenges.cloudflare.com/turnstile"],
    },
    "Cloudflare_Challenge": {
        "iframes": ['iframe[src*="challenges.cloudflare.com"]'],
        "elements": ["#challenge-form", "#challenge-running", ".challenge-page"],
        "scripts": ["challenges.cloudflare.com"],
    },
    "GeeTest": {
        "iframes": [],
        "elements": [".geetest_holder", ".geetest_widget", "#geetest-captcha"],
        "scripts": ["geetest.com", "gt.js"],
    },
    "KeyCAPTCHA": {
        "iframes": [],
        "elements": ["#keycaptcha", ".keycaptcha"],
        "scripts": ["keycaptcha.com"],
    },
    "TextCaptcha": {
        "iframes": [],
        "elements": [],
        "scripts": ["textcaptcha.com"],
    },
    "AWS_WAF_Captcha": {
        "iframes": [],
        "elements": ["#captcha-container", "#aws-waf-captcha"],
        "scripts": ["awswaf.com", "aws-waf-captcha"],
    },
    "PerimeterX": {
        "iframes": [],
        "elements": ["#px-captcha", "#px-block"],
        "scripts": ["perimeterx.net", "px-captcha"],
    },
    "DataDome": {
        "iframes": ['iframe[src*="datadome"]', 'iframe[src*="captcha-delivery.com"]'],
        "elements": [],
        "scripts": ["datadome.co", "captcha-delivery.com"],
    },
}

# Sites known to use each provider. These are real, publicly accessible sites
# that commonly present captchas under bot-like traffic patterns.
DEFAULT_TEST_SITES = [
    # reCAPTCHA
    {"url": "https://www.google.com/search?q=test", "label": "Google Search", "expected": "reCAPTCHA_v2"},
    {"url": "https://accounts.google.com", "label": "Google Accounts", "expected": "reCAPTCHA_v2"},
    {"url": "https://www.reddit.com/login", "label": "Reddit Login", "expected": "reCAPTCHA_v2"},
    # hCaptcha
    {"url": "https://discord.com/login", "label": "Discord Login", "expected": "hCaptcha"},
    {"url": "https://www.epicgames.com/id/login", "label": "Epic Games Login", "expected": "hCaptcha"},
    # Cloudflare
    {"url": "https://nowsecure.nl", "label": "NowSecure (CF)", "expected": "Cloudflare_Turnstile"},
    {"url": "https://www.sephora.com", "label": "Sephora", "expected": "Cloudflare_Challenge"},
    # FunCaptcha / Arkose Labs
    {"url": "https://www.roblox.com/login", "label": "Roblox Login", "expected": "FunCaptcha"},
    {"url": "https://outlook.live.com", "label": "Outlook Login", "expected": "FunCaptcha"},
    # DataDome
    {"url": "https://www.footlocker.com", "label": "Foot Locker", "expected": "DataDome"},
    # PerimeterX
    {"url": "https://www.zillow.com", "label": "Zillow", "expected": "PerimeterX"},
    # GeeTest
    {"url": "https://www.binance.com/en/login", "label": "Binance Login", "expected": "GeeTest"},
]


@dataclass
class SiteResult:
    """Result of probing a single site."""
    url: str
    label: str
    expected_provider: str
    captcha_detected: bool = False
    detected_providers: list = field(default_factory=list)
    http_status: int = 0
    blocked: bool = False
    load_time_ms: float = 0
    error: str | None = None


async def _detect_captcha_on_page(page: Page) -> list[str]:
    """Inspect the loaded page for captcha signatures. Returns provider names found."""
    found: list[str] = []

    # Fetch page HTML once for script-tag checks across all providers
    try:
        page_html = await page.content()
    except Exception:
        page_html = ""

    for provider, sigs in CAPTCHA_SIGNATURES.items():
        detected = False

        # Check iframes
        for sel in sigs["iframes"]:
            try:
                if await page.locator(sel).count() > 0:
                    detected = True
                    break
            except Exception:
                pass

        # Check DOM elements
        if not detected:
            for sel in sigs["elements"]:
                try:
                    if await page.locator(sel).count() > 0:
                        detected = True
                        break
                except Exception:
                    pass

        # Check script tags in the pre-fetched HTML
        if not detected and sigs["scripts"] and page_html:
            for script_sig in sigs["scripts"]:
                if script_sig in page_html:
                    detected = True
                    break

        if detected:
            found.append(provider)

    return found


async def _check_block_signals(page: Page, status: int) -> bool:
    """Heuristic: was the request outright blocked (403, 429, challenge page)?"""
    if status in (403, 429, 503):
        return True
    try:
        text = (await page.text_content("body") or "").lower()
        block_phrases = [
            "access denied",
            "you have been blocked",
            "please verify you are a human",
            "suspected automated",
            "unusual traffic",
            "ray id",            # Cloudflare block pages include a Ray ID
            "checking your browser",
        ]
        return any(p in text for p in block_phrases)
    except Exception:
        return False


async def probe_site(
    context: BrowserContext,
    url: str,
    label: str,
    expected: str,
    settle_delay: float = 3.0,
) -> SiteResult:
    """Open a URL in a new tab, wait for it to settle, detect captcha presence."""
    result = SiteResult(url=url, label=label, expected_provider=expected)
    page = await context.new_page()
    try:
        t0 = time.monotonic()
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
        result.http_status = resp.status if resp else 0
        # Give JS-injected captchas time to render
        await page.wait_for_timeout(int(settle_delay * 1000))
        result.load_time_ms = round((time.monotonic() - t0) * 1000, 1)

        result.detected_providers = await _detect_captcha_on_page(page)
        result.captcha_detected = len(result.detected_providers) > 0
        result.blocked = await _check_block_signals(page, result.http_status)
    except Exception as exc:
        result.error = str(exc)[:200]
        logger.debug("Error probing %s: %s", url, exc)
    finally:
        await page.close()
    return result


async def run_captcha_scan(
    sites: list[dict] | None = None,
    visits_per_site: int = 3,
    headless: bool = True,
    settle_delay: float = 3.0,
) -> list[SiteResult]:
    """
    Launch Firefox via Playwright, visit each site multiple times, detect captchas.

    Args:
        sites: List of dicts with keys url, label, expected. Falls back to DEFAULT_TEST_SITES.
        visits_per_site: How many times to load each site (to build a statistical sample).
        headless: Run browser headless (default True).
        settle_delay: Seconds to wait after DOM load before scanning.

    Returns:
        Flat list of SiteResult (one per visit).
    """
    sites = sites or DEFAULT_TEST_SITES
    results: list[SiteResult] = []

    async with async_playwright() as pw:
        browser = await pw.firefox.launch(headless=headless)
        context = await browser.new_context(
            viewport={"width": 1280, "height": 800},
            locale="en-US",
        )

        for site in sites:
            for visit in range(visits_per_site):
                logger.info(
                    "Visit %d/%d  %s", visit + 1, visits_per_site, site["label"]
                )
                res = await probe_site(
                    context,
                    site["url"],
                    site["label"],
                    site["expected"],
                    settle_delay=settle_delay,
                )
                results.append(res)
                # Small pause between visits to the same site
                if visit < visits_per_site - 1:
                    await asyncio.sleep(1.5)

        await context.close()
        await browser.close()

    return results

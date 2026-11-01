"""Open the link in an isolated headless browser and record where it really goes.

capture() is shared with page_analysis: one browser visit per URL, memoised for a
few minutes, so both tools can run in parallel without visiting the site twice.

Safety: a fresh incognito context per visit, downloads refused, images/media/fonts
not loaded, service workers blocked, and every request to a non-public host
(localhost, private ranges, cloud metadata) aborted. If any hop of the redirect
chain lands on a non-public host, the captured content is discarded.
"""
from __future__ import annotations

import asyncio
import logging
import time
from urllib.parse import urlsplit

from app.models import Finding, Target
from app.safety import is_public_host
from app.urls import registered_domain

log = logging.getLogger("scam_investigator.browser")

TOOL = "browser_trace"
SOURCE = "Headless browser redirect trace"

NAV_TIMEOUT_MS = 15000
SETTLE_MS = 2500  # time for JS / meta-refresh redirects after DOMContentLoaded
MAX_TEXT = 6000
CAPTURE_TTL = 300.0
MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")

_PAGE_PROBE = """() => {
  const inputs = [...document.querySelectorAll('input')];
  const attr = (el) => [el.type, el.name, el.id, el.placeholder, el.autocomplete].join(' ').toLowerCase();
  const count = (re) => inputs.filter((el) => re.test(attr(el))).length;
  const host = location.hostname;
  const forms = [...document.forms].map((f) => { try { return new URL(f.action, location.href).hostname; } catch (e) { return null; } });
  const links = [...document.querySelectorAll('a[href]')].map((a) => a.href);
  return {
    password_fields: inputs.filter((el) => el.type === 'password').length,
    otp_fields: count(/otp|one.?time|verification.?code/),
    card_fields: count(/card|cvv|cvc|expiry|cc-number|cc-exp|cc-csc/),
    pin_fields: count(/\\bpin\\b|mpin|upi.?pin/),
    phone_fields: count(/mobile|phone|tel/),
    form_count: forms.length,
    offsite_form_hosts: [...new Set(forms.filter((h) => h && h !== host))].slice(0, 5),
    apk_links: links.filter((h) => /\\.apk(\\?|#|$)/i.test(h)).slice(0, 5),
    text: document.body ? document.body.innerText.slice(0, %d) : ''
  };
}""" % MAX_TEXT


class BrowserUnavailable(Exception):
    pass


_pw = None
_browser = None
_browser_lock = asyncio.Lock()
_visit_slots = asyncio.Semaphore(2)  # keeps memory bounded
_captures: dict[str, tuple[float, asyncio.Task]] = {}


async def _get_browser():
    global _pw, _browser
    async with _browser_lock:
        if _browser is not None and _browser.is_connected():
            return _browser
        try:
            from playwright.async_api import async_playwright
            _pw = await async_playwright().start()
            _browser = await _pw.chromium.launch(headless=True, args=["--disable-dev-shm-usage"])
        except NotImplementedError as exc:
            # Windows + uvicorn --reload uses a selector event loop that cannot spawn subprocesses.
            raise BrowserUnavailable("the browser cannot start under this event loop "
                                     "(on Windows, run uvicorn without --reload)") from exc
        except Exception as exc:  # noqa: BLE001
            raise BrowserUnavailable(f"the browser could not start ({type(exc).__name__}); "
                                     "run 'python -m playwright install chromium'") from exc
        return _browser


async def shutdown() -> None:
    global _pw, _browser
    try:
        if _browser is not None:
            await _browser.close()
        if _pw is not None:
            await _pw.stop()
    except Exception:  # noqa: BLE001 - best effort on shutdown
        pass
    _pw = _browser = None


async def _guard(route) -> None:
    request = route.request
    if request.resource_type in ("image", "media", "font"):
        await route.abort()
        return
    if not await is_public_host(urlsplit(request.url).hostname):
        await route.abort("blockedbyclient")
        return
    await route.continue_()


async def _visit(url: str) -> dict:
    if not await is_public_host(urlsplit(url).hostname):
        return {"blocked": True, "reason": "link points to a private or local address; not opened"}
    browser = await _get_browser()
    async with _visit_slots:
        context = await browser.new_context(user_agent=MOBILE_UA, accept_downloads=False,
                                            service_workers="block", viewport={"width": 412, "height": 915})
        try:
            await context.route("**/*", _guard)
            page = await context.new_page()
            navigations: list[str] = []
            downloads: list[str] = []
            page.on("framenavigated", lambda f: navigations.append(f.url) if f == page.main_frame else None)
            page.on("download", lambda d: downloads.append(d.suggested_filename))
            started = time.monotonic()
            response = None
            nav_error = None
            try:
                response = await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                await page.wait_for_timeout(SETTLE_MS)
            except Exception as exc:  # noqa: BLE001 - downloads and dead sites end up here
                nav_error = type(exc).__name__ + ": " + str(exc).splitlines()[0][:200]

            http_chain: list[dict] = []
            request = response.request if response else None
            while request is not None:
                http_chain.insert(0, {"url": request.url})
                request = request.redirected_from
            if response is not None:
                http_chain[-1]["status"] = response.status

            final_url = page.url if page.url and page.url != "about:blank" else url
            hops = [h["url"] for h in http_chain] + navigations + [final_url]
            for hop in dict.fromkeys(hops):
                if not await is_public_host(urlsplit(hop).hostname):
                    return {"blocked": True, "reason": "a redirect led to a private or local address; "
                                                       "content discarded"}
            probe, title = {}, ""
            if nav_error is None:
                try:
                    title = (await page.title())[:200]
                    probe = await page.evaluate(_PAGE_PROBE)
                except Exception as exc:  # noqa: BLE001 - page navigated away mid-read, etc.
                    nav_error = type(exc).__name__
            return {
                "blocked": False,
                "requested_url": url,
                "final_url": final_url,
                "http_chain": http_chain,
                "navigations": list(dict.fromkeys(navigations))[:10],
                "status": response.status if response else None,
                "title": title,
                "probe": probe,
                "downloads": downloads,
                "error": nav_error,
                "elapsed_s": round(time.monotonic() - started, 1),
            }
        finally:
            await context.close()


def capture(url: str) -> asyncio.Task:
    """One shared visit per URL (memoised for CAPTURE_TTL seconds)."""
    now = time.monotonic()
    for key, (ts, _) in list(_captures.items()):
        if now - ts > CAPTURE_TTL:
            _captures.pop(key, None)
    cached = _captures.get(url)
    if cached:
        return cached[1]
    task = asyncio.create_task(_visit(url))

    def _index_final(t: asyncio.Task) -> None:
        if t.cancelled() or t.exception() is not None:
            _captures.pop(url, None)  # don't cache failures
            return
        final = t.result().get("final_url")
        if final and final not in _captures:
            _captures[final] = (time.monotonic(), t)

    task.add_done_callback(_index_final)
    _captures[url] = (now, task)
    return task


async def check(target: Target) -> Finding:
    try:
        cap = await asyncio.shield(capture(target.url))
    except BrowserUnavailable as exc:
        return Finding.unavailable(TOOL, SOURCE, f"Browser unavailable: {exc}.")
    request = {"url": target.url}
    if cap.get("blocked"):
        return Finding.new(TOOL, SOURCE, "error", f"Not opened: {cap['reason']}.", {"request": request})

    final_url = cap["final_url"]
    final_host = (urlsplit(final_url).hostname or "").lower()
    final_domain = registered_domain(final_host) if final_host else ""
    redirects = max(0, len(cap["http_chain"]) - 1) + max(0, len(cap["navigations"]) - 1)
    probe = cap.get("probe") or {}
    derived = {
        "final_url": final_url,
        "final_host": final_host,
        "final_registered_domain": final_domain,
        "redirect_count": redirects,
        "cross_domain": bool(final_domain) and final_domain != target.registered_domain,
        "password_fields": probe.get("password_fields", 0),
        "otp_fields": probe.get("otp_fields", 0),
        "card_fields": probe.get("card_fields", 0),
        "pin_fields": probe.get("pin_fields", 0),
        "offsite_form_hosts": probe.get("offsite_form_hosts", []),
        "apk_links": probe.get("apk_links", []),
        "download_attempts": cap.get("downloads", []),
    }
    response = {k: cap.get(k) for k in ("http_chain", "navigations", "status", "title", "error", "elapsed_s")}
    raw = {"request": request, "response": response, "derived": derived}

    if cap.get("error") and not cap.get("downloads") and final_url == target.url:
        return Finding.new(TOOL, SOURCE, "error", f"The page could not be loaded ({cap['error'][:120]}).", raw)

    parts = []
    if derived["cross_domain"] or final_host != target.host:
        parts.append(f"redirects ({redirects} hop{'s' if redirects != 1 else ''}) to {final_url}")
    else:
        parts.append(f"stays on {final_host}")
    if cap.get("title"):
        parts.append(f"page title '{cap['title']}'")
    fields = [name for name, n in (("password", derived["password_fields"]), ("OTP", derived["otp_fields"]),
                                   ("card/CVV", derived["card_fields"]), ("PIN", derived["pin_fields"])) if n]
    if fields:
        parts.append(f"page asks for {', '.join(fields)}")
    apk = derived["download_attempts"] or derived["apk_links"]
    if apk:
        parts.append(f"tries to deliver an Android app file ({apk[0]})")

    signal = "suspicious" if apk else "neutral"
    return Finding.new(TOOL, SOURCE, "ok", "Opened in an isolated browser: " + "; ".join(parts) + ".", raw, signal)

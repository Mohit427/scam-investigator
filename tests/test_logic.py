"""Offline tests for deterministic logic: URL handling, extraction regexes, lookalike
rules, escalation, budget planning, verdict guardrails, SSRF guard, rate limiting.

Findings built here are inputs to pure functions, not stand-ins for live API results.
"""
import unittest

from app.extraction import regex_extract
from app.models import CaseState, Finding, Reason, Target, Verdict
from app.orchestrator import _escalation, _plan
from app.ratelimit import RateLimiter
from app.safety import is_public_ip
from app.tools.lookalike import analyze
from app.urls import normalize_url
from app.verdict import finalize


def finding(tool: str, signal: str = "neutral", status: str = "ok", **derived) -> Finding:
    return Finding.new(tool, tool, status, "s", {"derived": derived} if derived else {}, signal)


def case_with(*findings: Finding, targets: int = 1) -> CaseState:
    case = CaseState()
    case.targets = [Target(url=f"http://t{i}.in/", host=f"t{i}.in", registered_domain=f"t{i}.in")
                    for i in range(targets)]
    for f in findings:
        case.add_finding(f)
    return case


class UrlTests(unittest.TestCase):
    def test_bare_domain_gets_scheme_and_trailing_punctuation_is_stripped(self):
        t = normalize_url("sbi-kyc.in/verify?id=9).")
        self.assertEqual(t.url, "http://sbi-kyc.in/verify?id=9")
        self.assertEqual(t.registered_domain, "sbi-kyc.in")

    def test_registered_domain_handles_multi_part_suffix(self):
        self.assertEqual(normalize_url("https://a.b.example.co.in/x").registered_domain, "example.co.in")

    def test_shortener_detected(self):
        self.assertTrue(normalize_url("https://bit.ly/abc").is_shortener)
        self.assertFalse(normalize_url("https://example.com").is_shortener)

    def test_rejects_non_web_and_local_targets(self):
        for raw in ("ftp://example.com", "javascript:alert(1)", "http://localhost:8000", "http://169.254.169.254/",
                    "http://10.0.0.1/admin", "notadomain"):
            self.assertIsNone(normalize_url(raw), raw)


class ExtractionRegexTests(unittest.TestCase):
    def test_finds_links_numbers_and_upi_but_not_emails(self):
        e = regex_extract("Update KYC: sbi-kyc.in/v or https://bit.ly/x. Call 9876543210, pay refund@okaxis. "
                          "Mail a.b@gmail.com e.g. Rs.500")
        self.assertIn("sbi-kyc.in/v", e.urls)
        self.assertTrue(any("bit.ly/x" in u for u in e.urls))
        self.assertNotIn("gmail.com", e.urls)
        self.assertEqual(e.phone_numbers, ["9876543210"])
        self.assertEqual(e.upi_ids, ["refund@okaxis"])

    def test_deobfuscates_defanged_links(self):
        self.assertIn("http://evil.com/x", regex_extract("go to hxxp://evil[.]com/x now").urls)


class LookalikeTests(unittest.TestCase):
    def test_official_and_restricted_domains_are_benign(self):
        self.assertEqual(analyze("netbanking.hdfcbank.com", "hdfcbank.com")[0], "benign")
        self.assertEqual(analyze("www.incometax.gov.in", "incometax.gov.in")[0], "benign")

    def test_brand_keyword_on_other_domain_is_suspicious(self):
        self.assertEqual(analyze("sbi-yono-kyc.in", "sbi-yono-kyc.in")[0], "suspicious")
        self.assertEqual(analyze("facebook.webmau.vn", "webmau.vn")[0], "suspicious")

    def test_homoglyphs_and_typos_are_suspicious(self):
        self.assertEqual(analyze("amaz0n-offer.shop", "amaz0n-offer.shop")[0], "suspicious")
        self.assertEqual(analyze("flipkrat.com", "flipkrat.com")[0], "suspicious")

    def test_short_keywords_need_a_whole_token(self):
        self.assertEqual(analyze("publicnews.in", "publicnews.in")[0], "neutral")  # contains "lic"
        self.assertEqual(analyze("example.com", "example.com")[0], "neutral")


class EscalationTests(unittest.TestCase):
    def test_conflict_escalates(self):
        self.assertTrue(_escalation([finding("virustotal", "malicious"), finding("rdap", "benign")])[0])

    def test_clear_malicious_stops(self):
        self.assertFalse(_escalation([finding("openphish", "malicious"), finding("virustotal", "malicious")])[0])

    def test_young_domain_escalates(self):
        self.assertTrue(_escalation([finding("rdap", "suspicious", age_days=5)])[0])

    def test_benign_only_stops_and_no_signal_escalates(self):
        self.assertFalse(_escalation([finding("lookalike", "benign"), finding("virustotal", "benign")])[0])
        self.assertTrue(_escalation([finding("safe_browsing"), finding("urlhaus")])[0])

    def test_failed_tools_are_ignored(self):
        self.assertTrue(_escalation([finding("virustotal", status="error"), finding("rdap", status="timeout")])[0])


class BudgetTests(unittest.TestCase):
    def test_local_tools_run_even_without_budget(self):
        case = CaseState(tool_calls=12)
        run, skipped = _plan(case, ["safe_browsing", "lookalike", "rdap"])
        self.assertEqual(run, ["lookalike"])
        self.assertEqual(skipped, ["safe_browsing", "rdap"])

    def test_budget_truncates_by_priority(self):
        case = CaseState(tool_calls=10)
        run, skipped = _plan(case, ["safe_browsing", "virustotal", "urlhaus"])
        self.assertEqual((run, skipped), (["safe_browsing", "virustotal"], ["urlhaus"]))


class FinalizeTests(unittest.TestCase):
    def verdict(self, label="likely_scam", conf=0.9, ids=("F1",)):
        return Verdict(verdict=label, confidence=conf, reasons=[Reason(text="r", finding_ids=list(ids))])

    def test_unknown_citation_dropped_and_verdict_softened(self):
        out = finalize(self.verdict(ids=("F9",)), case_with(finding("virustotal", "malicious")))
        self.assertEqual(out.reasons, [])
        self.assertEqual(out.verdict, "cannot_determine")

    def test_no_links_caps_confidence(self):
        out = finalize(self.verdict(conf=0.95), case_with(finding("message_analysis", "suspicious"), targets=0))
        self.assertEqual(out.confidence, 0.6)
        self.assertFalse(out.live_evidence)

    def test_all_live_tools_failed_forces_cannot_determine(self):
        case = case_with(finding("virustotal", status="error"), finding("lookalike", "suspicious"))
        out = finalize(self.verdict(ids=("F2",)), case)
        self.assertEqual(out.verdict, "cannot_determine")
        self.assertLessEqual(out.confidence, 0.3)

    def test_legitimate_with_malicious_finding_is_downgraded(self):
        out = finalize(self.verdict("likely_legitimate", 0.9), case_with(finding("openphish", "malicious")))
        self.assertEqual(out.verdict, "cannot_determine")

    def test_guidance_defaults_depend_on_links(self):
        no_link = finalize(self.verdict(), case_with(finding("message_analysis"), targets=0))
        self.assertNotIn("link", no_link.action_guidance[0].lower())


class SafetyTests(unittest.TestCase):
    def test_private_and_special_ips_are_not_public(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1", "169.254.169.254", "::1",
                   "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1", "fd00::1"):
            self.assertFalse(is_public_ip(ip), ip)
        self.assertTrue(is_public_ip("8.8.8.8"))


class RateLimitTests(unittest.TestCase):
    def test_per_client_window(self):
        now = [0.0]
        limiter = RateLimiter(limits=((60.0, 2),), clock=lambda: now[0])
        self.assertTrue(limiter.check("a")[0])
        self.assertTrue(limiter.check("a")[0])
        self.assertFalse(limiter.check("a")[0])
        self.assertTrue(limiter.check("b")[0])
        now[0] = 61.0
        self.assertTrue(limiter.check("a")[0])

    def test_concurrency_cap(self):
        limiter = RateLimiter(max_concurrent=1)
        limiter.active = 1
        self.assertFalse(limiter.check("a")[0])


if __name__ == "__main__":
    unittest.main()

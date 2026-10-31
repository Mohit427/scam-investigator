"""Tests for the Finding model and verdict citation validation (no network)."""
import unittest

from pydantic import ValidationError

from app.models import CaseState, Finding, Reason, Verdict, validate_citations


class FindingTests(unittest.TestCase):
    def test_new_sets_timestamp_and_defaults(self):
        f = Finding.new("rdap", "RDAP (rdap.org)", "ok", "summary", {"response": {}}, "benign")
        self.assertTrue(f.timestamp_utc.endswith("+00:00"))
        self.assertEqual(f.id, "")
        self.assertEqual(f.signal, "benign")

    def test_unavailable_is_neutral(self):
        f = Finding.unavailable("virustotal", "VirusTotal v3", "VIRUSTOTAL_API_KEY is not set.")
        self.assertEqual(f.status, "unavailable")
        self.assertEqual(f.signal, "neutral")

    def test_non_ok_finding_cannot_carry_a_signal(self):
        with self.assertRaises(ValidationError):
            Finding.new("urlhaus", "abuse.ch URLhaus", "error", "failed", signal="malicious")

    def test_rejects_unknown_status_and_signal(self):
        with self.assertRaises(ValidationError):
            Finding.new("x", "y", "maybe", "s")  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            Finding.new("x", "y", "ok", "s", signal="scary")  # type: ignore[arg-type]

    def test_case_assigns_sequential_ids(self):
        case = CaseState()
        a = case.add_finding(Finding.unavailable("a", "A", "why"))
        b = case.add_finding(Finding.unavailable("b", "B", "why"))
        self.assertEqual((a.id, b.id), ("F1", "F2"))
        self.assertEqual(set(case.findings), {"F1", "F2"})


class CitationTests(unittest.TestCase):
    def _verdict(self, reasons):
        return Verdict(verdict="likely_scam", confidence=0.8, reasons=reasons, action_guidance=["Block the sender."])

    def test_keeps_reasons_with_known_ids(self):
        v, dropped = validate_citations(self._verdict([Reason(text="ok", finding_ids=["F1", "F2"])]), {"F1", "F2"})
        self.assertEqual(dropped, 0)
        self.assertEqual(len(v.reasons), 1)

    def test_drops_reason_citing_unknown_id(self):
        reasons = [Reason(text="good", finding_ids=["F1"]), Reason(text="made up", finding_ids=["F1", "F9"])]
        v, dropped = validate_citations(self._verdict(reasons), {"F1"})
        self.assertEqual(dropped, 1)
        self.assertEqual([r.text for r in v.reasons], ["good"])

    def test_drops_reason_without_citations(self):
        v, dropped = validate_citations(self._verdict([Reason(text="no evidence", finding_ids=[])]), {"F1"})
        self.assertEqual(dropped, 1)
        self.assertEqual(v.reasons, [])

    def test_verdict_label_and_confidence_are_constrained(self):
        with self.assertRaises(ValidationError):
            Verdict(verdict="probably_fine", confidence=0.5)  # type: ignore[arg-type]
        with self.assertRaises(ValidationError):
            Verdict(verdict="likely_scam", confidence=1.5)


if __name__ == "__main__":
    unittest.main()

# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Static HTML/CSS/vanilla JS served by FastAPI from `static/`; no npm, no build step (user decision).
ReactBits effects are ported to vanilla JS from the ReactBits source; WebGL helpers may load from an
approved CDN with a pinned version.

## Users

Primary: everyday Indian phone users (SMS / WhatsApp) who just received a message they are unsure
about: a KYC update, a parcel fee, a job offer, a refund, a short link. Often on a phone, often
anxious, sometimes reading in Hinglish. Their job: find out, quickly, whether to trust it and what to
do next.

Secondary: hackathon judges evaluating whether the agent really investigates with live evidence.

## Product Purpose

Scam Investigator takes a pasted message or link, investigates it with live security sources, streams
every step as it happens, and returns a verdict (likely scam / likely legitimate / can't say) that
cites the exact evidence behind it, plus what to do next. Success: the citizen understands the answer
and the action within seconds of the verdict arriving, and can open the evidence behind every claim.

## Positioning

It does not guess from the text. Every finding comes from a real, live call (Google Safe Browsing,
VirusTotal, URLhaus, OpenPhish, RDAP domain age, crt.sh certificates, urlscan.io, a sandboxed browser
visit, page analysis) and every reason in the verdict links to the finding it rests on. When evidence
is thin it says "can't say" rather than bluffing.

## Operating Context

Single page: paste, investigate, watch the live trail, read the verdict. Typical inputs: Indian bank
KYC SMS, courier/customs fees, electricity disconnection, job/task scams, UPI refund requests, short
links (bit.ly etc.). India-specific next steps: cybercrime.gov.in, helpline 1930, Sanchar Saathi /
Chakshu.

## Capabilities and Constraints

- An investigation takes ~10–60 s; results stream in as server-sent events (step, finding, verdict).
- Verdict: one of three labels, confidence 0–1, cited reasons, action guidance, notes.
- Messages without links are judged from text only, capped at 60% confidence.
- Rate limit (configurable): 20 checks/minute, 200/hour per client, 6 cases at once.
- Hard rule: no mock or sample results anywhere in the UI. Example *inputs* may be offered; example
  findings/verdicts may not.

## Brand Commitments

Name: Scam Investigator. Voice: plain, calm, direct; never alarmist, never jokey about victims.

## Evidence on Hand

The list of live sources the tool really queries (above). No users, testimonials, press, usage
statistics or accuracy numbers exist; none may be invented.

## Product Principles

1. The answer comes first: once a check finishes, the verdict is on screen without scrolling.
2. Show the work: every claim is traceable to a live finding.
3. Honest uncertainty beats false confidence.
4. Calm under stress: the user may be frightened; the interface must not add to it.
5. Privacy by default: the message is never stored.

## Accessibility & Inclusion

WCAG 2.2 AA; works one-handed on low-end Android phones; respects reduced motion; readable for
non-native English readers.

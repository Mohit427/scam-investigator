"""In-memory abuse protection for /api/investigate (single-process deployments).

Each investigation can spend up to 12 paid/quota-limited API calls and a browser
visit, so we cap per-client request rates and the number running at once.
"""
from __future__ import annotations

import time
from collections import deque

PER_CLIENT_LIMITS = ((60.0, 20), (3600.0, 200))  # (window seconds, max requests)
MAX_CONCURRENT = 6


class RateLimiter:
    def __init__(self, limits=PER_CLIENT_LIMITS, max_concurrent: int = MAX_CONCURRENT,
                 clock=time.monotonic) -> None:
        self.limits = limits
        self.max_concurrent = max_concurrent
        self.clock = clock
        self.active = 0
        self._hits: dict[str, deque[float]] = {}

    def check(self, client: str) -> tuple[bool, str, int]:
        """Returns (allowed, reason, retry_after_seconds). Records the hit if allowed."""
        now = self.clock()
        longest = max(window for window, _ in self.limits)
        hits = self._hits.setdefault(client, deque())
        while hits and now - hits[0] > longest:
            hits.popleft()
        for window, limit in self.limits:
            recent = [t for t in hits if now - t <= window]
            if len(recent) >= limit:
                retry = int(window - (now - recent[0])) + 1
                return False, f"Too many checks from your connection. Please try again in {retry} seconds.", retry
        if self.active >= self.max_concurrent:
            return False, "The investigator is busy with other checks. Please try again in a few seconds.", 5
        hits.append(now)
        if len(self._hits) > 10_000:  # bound memory: forget idle clients
            for key in [k for k, v in self._hits.items() if not v or now - v[-1] > longest]:
                del self._hits[key]
        return True, "", 0

# CrawlLens — HTTP session and politeness helpers
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import threading
import time
from typing import Dict
import requests
from ..utils.net import build_session


class HostPacer:
	"""Per-host pacing using monotonic timestamps.

	Thread-safe; call before each request.
	"""

	def __init__(self) -> None:
		self._lock = threading.Lock()
		self._last: Dict[str, float] = {}

	def wait(self, host: str, min_delay: float) -> None:
		with self._lock:
			last = self._last.get(host)
			now = time.monotonic()
			if last is not None and min_delay > 0:
				remaining = min_delay - (now - last)
				if remaining > 0:
					# small sleep loop to remain interruptible by caller
					end = now + remaining
					while time.monotonic() < end:
						time.sleep(0.05)
			self._last[host] = time.monotonic()


def make_session(user_agent: str, retries: int, backoff: float) -> requests.Session:
	return build_session(user_agent=user_agent, retries=retries, backoff=backoff)

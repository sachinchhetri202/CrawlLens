# CrawlLens — Networking utilities (requests session with retries)
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def build_session(user_agent: str, retries: int = 3, backoff: float = 0.5) -> requests.Session:
	"""Build a requests Session with respectful defaults and Retry.

	Handles urllib3 v1/v2 difference for Retry.allowed_methods (frozenset vs tuple).
	"""
	s = requests.Session()
	s.headers.update(
		{
			"User-Agent": user_agent,
			"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
		}
	)
	allowed = {"GET", "HEAD"}
	try:
		retry = Retry(
			total=retries,
			backoff_factor=backoff,
			status_forcelist=(429, 500, 502, 503, 504),
			allowed_methods=allowed,  # urllib3 v2 prefers set/frozenset
		)
	except TypeError:
		retry = Retry(
			total=retries,
			backoff_factor=backoff,
			status_forcelist=(429, 500, 502, 503, 504),
			allowed_methods=("GET", "HEAD"),  # urllib3 v1 compatibility
		)
	adapter = HTTPAdapter(max_retries=retry)
	s.mount("http://", adapter)
	s.mount("https://", adapter)
	return s

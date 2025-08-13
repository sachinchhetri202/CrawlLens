# CrawlLens — Robots.txt etiquette and checks
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser
from typing import List, Tuple


def fetch_and_parse_robots(session, base_url: str) -> Tuple[bool, float, str, List[str], RobotFileParser]:
	"""Fetch robots.txt once, parse allow/deny, crawl-delay, and sitemaps.

	Returns: (is_allowed, delay, robots_url, sitemaps, rp)
	Conservative defaults on network errors.
	"""
	try:
		p = urlparse(base_url)
		robots_url = urljoin(f"{p.scheme}://{p.netloc}", "/robots.txt")
		rp = RobotFileParser()
		sitemaps: List[str] = []
		r = session.get(robots_url, timeout=10)
		r.raise_for_status()
		lines = r.text.splitlines()
		for line in lines:
			if line.lower().startswith("sitemap:"):
				try:
					sm = line.split(":", 1)[1].strip()
					if sm:
						sitemaps.append(sm)
				except Exception:
					pass
		rp.parse(lines)
		ua = session.headers.get("User-Agent", "*")
		allowed = rp.can_fetch(ua, base_url)
		delay = rp.crawl_delay(ua)
		if delay is None:
			delay = 1.0
		return bool(allowed), float(delay), robots_url, sitemaps, rp
	except Exception:
		return True, 2.0, "", [], RobotFileParser()


def can_fetch_url(session, url: str) -> bool:
	try:
		p = urlparse(url)
		robots_url = urljoin(f"{p.scheme}://{p.netloc}", "/robots.txt")
		r = session.get(robots_url, timeout=6)
		r.raise_for_status()
		rp = RobotFileParser()
		rp.parse(r.text.splitlines())
		return rp.can_fetch(session.headers.get("User-Agent", "*"), url)
	except Exception:
		return True

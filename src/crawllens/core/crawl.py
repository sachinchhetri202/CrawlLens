# CrawlLens — Core crawler (BFS, robots, pacing, extraction)
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import logging
import re
import time
from collections import deque
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

from .session import HostPacer, make_session
from .robots import fetch_and_parse_robots, can_fetch_url
from .sitemap import discover_urls_from_sitemaps
from .extract import parse_html, extract_page
from ..utils.urls import normalize_url, same_domain, same_site
from ..storage.writers import DatasetWriters


logger = logging.getLogger(__name__)


class CrawlOptions:
	def __init__(
		self,
		max_depth: int = 0,
		min_delay: float = 2.0,
		same_domain_only: bool = True,
		same_site_only: bool = False,
		use_sitemaps: bool = True,
		export_jsonl: bool = True,
		export_blocks: bool = True,
		compact_blocks: bool = True,
		link_check_limit: int = 20,
	):
		self.max_depth = max_depth
		self.min_delay = max(0.0, float(min_delay))
		self.same_domain_only = same_domain_only
		self.same_site_only = same_site_only
		self.use_sitemaps = use_sitemaps
		self.export_jsonl = export_jsonl
		self.export_blocks = export_blocks
		self.compact_blocks = compact_blocks
		self.link_check_limit = max(1, int(link_check_limit))


class CrawlResult:
	def __init__(self) -> None:
		self.pages_count = 0
		self.blocks_count = 0
		self.tables_count = 0
		self.last_export_path: str = ""
		self.sitemaps: List[str] = []


class Crawler:
	"""Depth-limited, polite BFS crawler with export support."""

	def __init__(self, user_agent: str, data_dir: str, retries: int = 3, backoff: float = 0.5) -> None:
		self.session = make_session(user_agent=user_agent, retries=retries, backoff=backoff)
		self.pacer = HostPacer()
		self.writers = DatasetWriters(data_dir=data_dir)
		self._robots_cache: Dict[str, Tuple[object, float]] = {}

	def check_robots(self, base_url: str) -> Tuple[bool, float, str, List[str]]:
		allowed, delay, robots_url, sitemaps, rp = fetch_and_parse_robots(self.session, base_url)
		try:
			self._robots_cache[urlparse(base_url).netloc] = (rp, float(delay))
		except Exception:
			pass
		return allowed, delay, robots_url, sitemaps

	def _respect_rate_limit(self, url: str, default_delay: float) -> None:
		host = urlparse(url).netloc
		robots_delay = 0.0
		try:
			robots_delay = float(self._robots_cache.get(host, (None, 0.0))[1] or 0.0)
		except Exception:
			robots_delay = 0.0
		delay = max(default_delay, robots_delay)
		self.pacer.wait(host, delay)

	def _head_allows_html(self, url: str) -> bool:
		try:
			r = self.session.head(url, allow_redirects=True, timeout=10)
			ctype = r.headers.get("Content-Type", "")
			return "text/html" in ctype
		except Exception:
			return True  # be permissive; GET will recheck

	def _get_html(self, url: str):
		r = self.session.get(url, timeout=15)
		r.raise_for_status()
		ctype = r.headers.get("Content-Type", "")
		if "text/html" not in ctype:
			raise ValueError(f"non-HTML content: {ctype}")
		if len(r.content) > 3 * 1024 * 1024:
			raise ValueError("page >3MB")
		return r

	def crawl(self, seed: str, options: CrawlOptions, stop_flag: Optional[callable] = None) -> CrawlResult:
		res = CrawlResult()
		seed_norm = normalize_url(seed)
		allowed, robots_delay, _, sitemaps = self.check_robots(seed_norm)
		res.sitemaps = sitemaps
		if not allowed:
			logger.warning("Disallowed by robots.txt: %s", seed_norm)
			return res
		base_delay = max(options.min_delay, float(robots_delay or 0.0))
		base_netloc = urlparse(seed_norm).netloc
		seen: Set[str] = set()
		dq: deque[Tuple[str, int]] = deque()
		dq.append((seed_norm, 0))

		if sitemaps and options.use_sitemaps and options.max_depth > 0:
			try:
				sm_urls = discover_urls_from_sitemaps(self.session, sitemaps, limit=500)
				for u in sm_urls:
					nu = normalize_url(u)
					if nu in seen:
						continue
					if options.same_site_only and not same_site(nu, seed_norm):
						continue
					if options.same_domain_only and not same_domain(nu, seed_norm):
						continue
					dq.append((nu, 1))
			except Exception:
				pass

		while dq:
			if stop_flag and stop_flag():
				break
			url, depth = dq.popleft()
			if url in seen:
				continue
			seen.add(url)
			if not can_fetch_url(self.session, url):
				logger.info("Disallowed by robots: %s", url)
				continue
			self._respect_rate_limit(url, base_delay)
			# HEAD gate
			if not self._head_allows_html(url):
				continue
			try:
				r = self._get_html(url)
				soup = parse_html(r.content)
				# meta robots
				meta_robots = ''
				try:
					mr = soup.find('meta', attrs={'name': re.compile(r'^robots$', re.I)})
					if mr:
						meta_robots = (mr.get('content') or '').lower()
				except Exception:
					meta_robots = ''
				nofollow = ('nofollow' in meta_robots)
				noindex = ('noindex' in meta_robots)
				page_obj, blocks, internal_links = extract_page(url, r, soup)
				# honor X-Robots-Tag: noindex for exports
				xrobots = (r.headers.get('X-Robots-Tag', '') or '').lower()
				if options.export_jsonl and not noindex and 'noindex' not in xrobots:
					text_sha1 = page_obj.get('hashes', {}).get('text_sha1', '')
					if text_sha1 and not self.writers.has_text_hash(text_sha1):
						self.writers.append_hash(text_sha1)
						path = self.writers.write_html(page_obj['doc_id'], r.content)
						res.last_export_path = path
						self.writers.write_page(page_obj)
						res.pages_count += 1
						if options.export_blocks and blocks:
							ctx = {"doc_id": page_obj['doc_id'], "url": page_obj['url'], "title": page_obj.get('title',''), "lang": page_obj.get('lang','')}
							if options.compact_blocks:
								self.writers.write_blocks_compact(ctx, blocks)
							else:
								self.writers.write_blocks_enriched(ctx, blocks)
							res.blocks_count += len(blocks)
							res.tables_count += sum(1 for b in blocks if b.get('type') == 'table')
			except Exception as e:
				logger.warning("Skipping %s due to error: %s", url, e)
				internal_links = []
			if depth < options.max_depth and not nofollow:
				for link in internal_links:
					if stop_flag and stop_flag():
						break
					try:
						if options.same_site_only and not same_site(link, seed_norm):
							continue
						if options.same_domain_only and urlparse(link).netloc != urlparse(seed_norm).netloc:
							continue
						ln = normalize_url(link)
						if ln not in seen:
							dq.append((ln, depth + 1))
					except Exception:
						continue
		return res

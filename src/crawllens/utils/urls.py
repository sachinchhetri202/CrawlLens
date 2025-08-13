# CrawlLens — URL utilities: normalization and scope checks
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

from urllib.parse import urlparse, urlunparse, urljoin, parse_qsl, urlencode
import re

try:
	import tldextract  # optional
except Exception:  # pragma: no cover - optional
	tldextract = None


TRACKING_PARAMS = {
	"utm_source",
	"utm_medium",
	"utm_campaign",
	"utm_term",
	"utm_content",
	"gclid",
	"fbclid",
}


def normalize_url(url: str) -> str:
	"""Normalize URL: strip fragments, lower scheme/host, drop tracking params, collapse slashes.
	Fallbacks to original URL on errors.
	"""
	try:
		p = urlparse(url)
		p = p._replace(fragment="")
		q = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=False) if k.lower() not in TRACKING_PARAMS]
		new_q = urlencode(q, doseq=True)
		netloc = p.netloc.lower()
		scheme = p.scheme.lower() if p.scheme else "https"
		p = p._replace(query=new_q, netloc=netloc, scheme=scheme)
		# default ports
		if p.netloc.endswith(":80") and p.scheme == "http":
			p = p._replace(netloc=p.netloc[:-3])
		if p.netloc.endswith(":443") and p.scheme == "https":
			p = p._replace(netloc=p.netloc[:-4])
		# path slashes
		path = re.sub(r"/+", "/", p.path or "/")
		p = p._replace(path=path)
		return urlunparse(p)
	except Exception:
		return url


def same_domain(url_a: str, url_b: str) -> bool:
	try:
		return urlparse(url_a).netloc.lower() == urlparse(url_b).netloc.lower()
	except Exception:
		return False


def etld_plus_one(netloc: str) -> str:
	try:
		if not tldextract:
			return netloc
		ext = tldextract.extract(netloc)
		return ".".join([p for p in [ext.domain, ext.suffix] if p])
	except Exception:
		return netloc


def same_site(url_a: str, url_b: str) -> bool:
	try:
		return etld_plus_one(urlparse(url_a).netloc) == etld_plus_one(urlparse(url_b).netloc)
	except Exception:
		return False


__all__ = [
	"normalize_url",
	"same_domain",
	"same_site",
	"etld_plus_one",
	"urljoin",
]

# CrawlLens — Sitemap discovery and parsing
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

from typing import Iterable, List
import xml.etree.ElementTree as ET


def discover_urls_from_sitemaps(session, sitemap_urls: Iterable[str], limit: int = 1000) -> List[str]:
	discovered: List[str] = []
	for sm in sitemap_urls:
		if len(discovered) >= limit:
			break
		try:
			r = session.get(sm, timeout=12)
			r.raise_for_status()
			root = ET.fromstring(r.text)
			if root.tag.endswith("urlset"):
				for loc in root.findall('.//{*}loc'):
					if len(discovered) >= limit:
						break
					u = (loc.text or '').strip()
					if u:
						discovered.append(u)
			elif root.tag.endswith("sitemapindex"):
				for loc in root.findall('.//{*}loc'):
					child = (loc.text or '').strip()
					if not child:
						continue
					try:
						r2 = session.get(child, timeout=12)
						r2.raise_for_status()
						root2 = ET.fromstring(r2.text)
						for loc2 in root2.findall('.//{*}loc'):
							if len(discovered) >= limit:
								break
							u2 = (loc2.text or '').strip()
							if u2:
								discovered.append(u2)
					except Exception:
						continue
		except Exception:
			continue
	return discovered

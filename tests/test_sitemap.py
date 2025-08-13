import xml.etree.ElementTree as ET
from crawllens.core.sitemap import discover_urls_from_sitemaps


class MockSession:
	def __init__(self, mapping):
		self.mapping = mapping

	def get(self, url, timeout=12):
		class R:
			def __init__(self, text, status_code=200):
				self.text = text
				self.status_code = status_code

			def raise_for_status(self):
				if self.status_code >= 400:
					raise RuntimeError("bad")

		return R(self.mapping[url])


def test_discover_from_urlset():
	xml = """
		<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
			<url><loc>https://example.com/a</loc></url>
			<url><loc>https://example.com/b</loc></url>
		</urlset>
	"""
	s = MockSession({"https://example.com/sitemap.xml": xml})
	urls = discover_urls_from_sitemaps(s, ["https://example.com/sitemap.xml"], limit=10)
	assert urls == ["https://example.com/a", "https://example.com/b"]

from urllib.robotparser import RobotFileParser


def test_robots_allow_deny():
	rp = RobotFileParser()
	rp.parse(
		[
			"User-agent: *",
			"Disallow: /private",
			"Allow: /",
		]
	)
	assert rp.can_fetch("CrawlLens/0.1", "https://example.com/")
	assert not rp.can_fetch("CrawlLens/0.1", "https://example.com/private/area")

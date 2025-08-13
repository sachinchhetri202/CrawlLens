from crawllens.core.extract import parse_html, extract_outline_and_blocks


def test_basic_block_extraction():
	html = b"""
	<html><body>
	<h1>Title</h1>
	<p>Hello world.</p>
	<ul><li>One</li><li>Two</li></ul>
	<table><tr><th>A</th><th>B</th></tr><tr><td>1</td><td>2</td></tr></table>
	</body></html>
	"""
	soup = parse_html(html)
	outline, blocks = extract_outline_and_blocks(soup)
	types = [b['type'] for b in blocks]
	assert 'heading' in types
	assert 'paragraph' in types
	assert 'list' in types
	assert 'table' in types

# CrawlLens — Extraction: outline, blocks, and block records
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


PARSER_CANDIDATES = ["lxml", "html.parser"]


def parse_html(content: bytes) -> BeautifulSoup:
	"""Parse HTML using lxml if available, else builtin parser."""
	for parser in PARSER_CANDIDATES:
		try:
			return BeautifulSoup(content, parser)
		except Exception:
			continue
	return BeautifulSoup(content, "html.parser")


def css_dom_path(el) -> str:
	try:
		parts = []
		node = el
		while node and getattr(node, 'name', None) and node.name != 'html':
			try:
				index = len(node.find_previous_siblings(node.name)) + 1
			except Exception:
				index = 1
			parts.append(f"{node.name}[{index}]")
			node = node.parent
		parts.append('html[1]')
		return '>'.join(reversed(parts))
	except Exception:
		return ''


def list_to_struct(list_el) -> Dict[str, Any]:
	items = []
	for li in list_el.find_all('li', recursive=False):
		itxt = ' '.join(li.get_text(' ', strip=True).split())
		if itxt:
			items.append(itxt)
	return {"items": items, "as_text": "\n".join(["• " + i for i in items])}


def table_to_struct(table_el) -> Dict[str, Any]:
	caption = ''
	headers: List[str] = []
	rows: List[List[str]] = []
	cap = table_el.find('caption')
	if cap:
		caption = ' '.join(cap.get_text(' ', strip=True).split())
	thead = table_el.find('thead')
	if thead:
		tr = thead.find('tr')
		if tr:
			for th in tr.find_all(['th', 'td']):
				headers.append(' '.join(th.get_text(' ', strip=True).split()))
	if not headers:
		first_tr = table_el.find('tr')
		if first_tr:
			ths = first_tr.find_all('th')
			tds = first_tr.find_all('td')
			if ths and not tds:
				headers = [' '.join(th.get_text(' ', strip=True).split()) for th in ths]
	for tr in table_el.find_all('tr'):
		cells = [' '.join(td.get_text(' ', strip=True).split()) for td in tr.find_all(['td', 'th'])]
		if cells:
			rows.append(cells)
	as_md = ''
	if headers:
		as_md += '| ' + ' | '.join(headers) + ' |\n'
		as_md += '| ' + ' | '.join(['---'] * len(headers)) + ' |\n'
		start_idx = 1 if rows and len(rows[0]) == len(headers) else 0
		for r in rows[start_idx:]:
			as_md += '| ' + ' | '.join(r) + ' |\n'
	else:
		for r in rows:
			as_md += '| ' + ' | '.join(r) + ' |\n'
	return {"caption": caption, "headers": headers, "rows": rows, "as_markdown": as_md}


def extract_outline_and_blocks(soup: BeautifulSoup) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
	body = soup.find('body') or soup
	outline: List[Dict[str, Any]] = []
	blocks: List[Dict[str, Any]] = []
	section_counters = [0, 0, 0, 0, 0, 0]
	current_stack: List[Tuple[int, str, str]] = []
	heading_tags = {f'h{i}' for i in range(1, 7)}
	content_tags = heading_tags.union({'p', 'ul', 'ol', 'pre', 'code', 'table'})
	all_nodes = list(body.descendants)
	i = 0

	def next_section_id(level: int) -> str:
		idx = level - 1
		section_counters[idx] += 1
		for j in range(idx + 1, 6):
			section_counters[j] = 0
		parts = []
		for j in range(0, level):
			if section_counters[j] == 0:
				continue
			parts.append(str(section_counters[j]))
		return 's' + '.'.join(parts)

	def current_section_path() -> str:
		if not current_stack:
			return ''
		return ' > '.join([f"H{lvl}:{txt}" for (lvl, sid, txt) in current_stack])

	def nearest_section_id() -> str:
		if not current_stack:
			return ''
		return current_stack[-1][1]

	while i < len(all_nodes):
		node = all_nodes[i]
		i += 1
		if getattr(node, 'name', None) not in content_tags:
			continue
		if node.name in heading_tags:
			try:
				level = int(node.name[1])
				text = ' '.join(node.get_text(' ', strip=True).split())
				sid = next_section_id(level)
				while current_stack and current_stack[-1][0] >= level:
					current_stack.pop()
				current_stack.append((level, sid, text))
				outline.append({"id": sid, "level": level, "text": text})
				blocks.append({
					"block_id": "",
					"type": "heading",
					"level": level,
					"section_id": sid,
					"section_path": current_section_path(),
					"dom_path": css_dom_path(node),
					"text": text,
				})
			except Exception:
				continue
			continue
		sect_id = nearest_section_id()
		sect_path = current_section_path()
		if node.name == 'p':
			text = ' '.join(node.get_text(' ', strip=True).split())
			if not text:
				continue
			blocks.append({
				"block_id": "",
				"type": "paragraph",
				"section_id": sect_id,
				"section_path": sect_path,
				"dom_path": css_dom_path(node),
				"text": text,
			})
		elif node.name in ('ul', 'ol'):
			lst = list_to_struct(node)
			if not lst.get('items'):
				continue
			blocks.append({
				"block_id": "",
				"type": "list",
				"section_id": sect_id,
				"section_path": sect_path,
				"dom_path": css_dom_path(node),
				"text": lst.get('as_text', ''),
				"items": lst.get('items', []),
				"as_text": lst.get('as_text', ''),
			})
		elif node.name in ('pre', 'code'):
			raw = node.get_text('\n', strip=False)
			text = ' '.join(raw.split())
			blocks.append({
				"block_id": "",
				"type": "code",
				"section_id": sect_id,
				"section_path": sect_path,
				"dom_path": css_dom_path(node),
				"text": text,
				"language": "",
				"raw": raw,
			})
		elif node.name == 'table':
			tbl = table_to_struct(node)
			blocks.append({
				"block_id": "",
				"type": "table",
				"section_id": sect_id,
				"section_path": sect_path,
				"dom_path": css_dom_path(node),
				"caption": tbl.get('caption', ''),
				"headers": tbl.get('headers', []),
				"rows": tbl.get('rows', []),
				"as_markdown": tbl.get('as_markdown', ''),
			})
	for idx, b in enumerate(blocks, start=1):
		b['block_id'] = f"b{idx}"
	return outline, blocks


def build_block_records_for_jsonl(page_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
	MAX_TOKENS_PER_CHUNK = 1500
	OVERLAP_TOKENS = 150

	def est_tokens(text: str) -> int:
		return max(1, int(len(text) / 4))

	records: List[Dict[str, Any]] = []
	for b in page_obj.get('blocks', []):
		rec = {
			"doc_id": page_obj['doc_id'],
			"url": page_obj['url'],
			"title": page_obj.get('title', ''),
			"lang": page_obj.get('lang', ''),
			"block_id": b.get('block_id', ''),
			"type": b.get('type'),
			"section_id": b.get('section_id', ''),
			"section_path": b.get('section_path', ''),
			"dom_path": b.get('dom_path', ''),
		}
		for key in ('text', 'items', 'as_text', 'level', 'language', 'raw', 'caption', 'headers', 'rows', 'as_markdown'):
			if key in b:
				rec[key] = b[key]
		records.append(rec)
		if b.get('type') == 'paragraph':
			text = b.get('text', '')
			if est_tokens(text) > MAX_TOKENS_PER_CHUNK:
				parts = re.split(r"\n\n+|(?<=[.!?])\s+", text)
				chunks: List[str] = []
				current: List[str] = []
				current_tokens = 0
				for part in parts:
					pt = est_tokens(part)
					if current_tokens + pt > MAX_TOKENS_PER_CHUNK and current:
						chunks.append(' '.join(current))
						# overlap by last sentences
						overlap_tokens = 0
						overlap: List[str] = []
						for prev in reversed(current):
							overlap_tokens += est_tokens(prev)
							overlap.insert(0, prev)
							if overlap_tokens >= OVERLAP_TOKENS:
								break
						current = overlap[:]
						current_tokens = sum(est_tokens(x) for x in current)
					current.append(part)
					current_tokens += pt
				if current:
					chunks.append(' '.join(current))
				total = max(1, len(chunks))
				for idx, ch in enumerate(chunks):
					records.append({
						"doc_id": page_obj['doc_id'],
						"url": page_obj['url'],
						"title": page_obj.get('title', ''),
						"lang": page_obj.get('lang', ''),
						"block_id": f"{b.get('block_id', '')}-c{idx+1}",
						"type": "paragraph_chunk",
						"section_id": b.get('section_id', ''),
						"section_path": b.get('section_path', ''),
						"dom_path": b.get('dom_path', ''),
						"text": ch,
						"chunk_index": idx,
						"chunk_total": total,
					})
	return records


def extract_page(url: str, response, soup: BeautifulSoup) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[str]]:
	canonical_url = ''
	try:
		link_canonical = soup.find('link', rel=lambda v: v and 'canonical' in v)
		if link_canonical:
			canonical_url = link_canonical.get('href', '').strip()
	except Exception:
		canonical_url = ''
	effective_url = canonical_url or (response.url or url)
	title_el = soup.find('title')
	title_text = (title_el.get_text(strip=True) if title_el else '').strip()
	outline, blocks = extract_outline_and_blocks(soup)
	html_tag = soup.find('html')
	lang = html_tag.get('lang', '').strip() if html_tag and html_tag.has_attr('lang') else ''
	meta_desc_el = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
	meta_desc = meta_desc_el.get('content', '').strip() if meta_desc_el else ''
	robots_meta = 'index,follow'
	try:
		mr = soup.find('meta', attrs={'name': re.compile(r'^robots$', re.I)})
		if mr and mr.get('content'):
			robots_meta = mr.get('content').strip()
	except Exception:
		pass
	word_count = len((soup.find('body').get_text(' ', strip=True) if soup.find('body') else '').split())
	heading_counts = {f"h{i}": len(soup.find_all(f'h{i}')) for i in range(1, 7)}
	internal_links: List[str] = []
	external_links: List[str] = []
	for a in soup.find_all('a', href=True):
		resolved = urljoin(effective_url, a.get('href', ''))
		if not resolved.startswith(('http://', 'https://')):
			continue
		if urlparse(resolved).netloc == urlparse(effective_url).netloc:
			internal_links.append(resolved)
		else:
			external_links.append(resolved)
	page_text_parts: List[str] = []
	for b in blocks:
		if b['type'] == 'paragraph':
			page_text_parts.append(b.get('text', ''))
		elif b['type'] == 'list':
			page_text_parts.extend(b.get('items', []))
		elif b['type'] == 'code':
			page_text_parts.append(b.get('text', ''))
		elif b['type'] == 'table':
			page_text_parts.append(b.get('as_markdown', ''))
		elif b['type'] == 'heading':
			page_text_parts.append(b.get('text', ''))
	page_text = '\n\n'.join([p for p in page_text_parts if p])
	text_sha1 = hashlib.sha1(page_text.encode('utf-8', errors='ignore')).hexdigest() if page_text else hashlib.sha1((effective_url or '').encode('utf-8')).hexdigest()
	page_md5 = hashlib.md5((response.text or '').encode('utf-8', errors='ignore')).hexdigest()
	doc_id = hashlib.sha1((canonical_url or effective_url or url).encode('utf-8')).hexdigest()[:16]
	page_obj = {
		"doc_id": doc_id,
		"url": effective_url,
		"canonical_url": canonical_url or effective_url,
		"fetched_at": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
		"title": title_text,
		"lang": lang,
		"meta": {
			"description": meta_desc,
			"robots": robots_meta,
			"word_count": word_count,
			"heading_counts": heading_counts,
		},
		"outline": outline,
		"blocks": blocks,
		"links": {
			"internal": list({l for l in internal_links}),
			"external": list({l for l in external_links}),
		},
		"hashes": {
			"page_md5": page_md5,
			"text_sha1": text_sha1,
		},
		"source_html_path": f"data/html/{doc_id}.html",
	}
	block_records = build_block_records_for_jsonl(page_obj)
	return page_obj, block_records, internal_links

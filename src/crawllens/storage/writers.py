# CrawlLens — Dataset writers (JSONL, HTML, hash index)
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import hashlib
import os
from typing import Dict, Any, Iterable
from .history import ScrapingHistory
from ..utils.io import ensure_dirs, append_jsonl


class DatasetWriters:
	"""Helpers to persist dataset artifacts in a consistent structure under data_dir."""

	def __init__(self, data_dir: str = "data") -> None:
		self.data_dir = data_dir
		self.index_path = os.path.join(self.data_dir, "index", "hashes.txt")
		self.pages_path = os.path.join(self.data_dir, "jsonl", "pages.jsonl")
		self.blocks_path = os.path.join(self.data_dir, "jsonl", "blocks.jsonl")
		self.html_dir = os.path.join(self.data_dir, "html")
		ensure_dirs(self.html_dir, os.path.dirname(self.pages_path), os.path.dirname(self.index_path))
		self._hash_cache = self._load_hash_index()

	def _load_hash_index(self) -> set:
		index = set()
		try:
			if os.path.exists(self.index_path):
				with open(self.index_path, "r", encoding="utf-8") as f:
					for line in f:
						h = line.strip()
						if h:
							index.add(h)
		except Exception:
			return set()
		return index

	def append_hash(self, sha1_hex: str) -> None:
		self._hash_cache.add(sha1_hex)
		with open(self.index_path, "a", encoding="utf-8") as f:
			f.write(sha1_hex + "\n")

	def has_text_hash(self, sha1_hex: str) -> bool:
		return sha1_hex in self._hash_cache

	def write_html(self, doc_id: str, content: bytes) -> str:
		path = os.path.join(self.html_dir, f"{doc_id}.html")
		with open(path, "wb") as f:
			f.write(content)
		return path

	def write_page(self, page_obj: Dict[str, Any]) -> None:
		append_jsonl(self.pages_path, page_obj)

	def write_blocks_compact(self, page_ctx: Dict[str, Any], blocks: Iterable[Dict[str, Any]]) -> None:
		for b in blocks:
			minimal = {
				"doc_id": page_ctx.get("doc_id"),
				"url": page_ctx.get("url"),
				"title": page_ctx.get("title", ""),
				"lang": page_ctx.get("lang", ""),
				"block_id": b.get("block_id", ""),
				"type": b.get("type"),
				"section_id": b.get("section_id", ""),
			}
			t = b.get("type")
			if t in ("paragraph", "heading"):
				minimal["text"] = b.get("text", "")
			if t == "heading":
				minimal["level"] = b.get("level")
			if t == "list":
				minimal["items"] = b.get("items", [])
				minimal["as_text"] = b.get("as_text", "")
			if t == "code":
				minimal["raw"] = b.get("raw", "")
				minimal["language"] = b.get("language", "")
				minimal["text"] = b.get("text", "")
			if t == "table":
				minimal["caption"] = b.get("caption", "")
				minimal["headers"] = b.get("headers", [])
				minimal["rows"] = b.get("rows", [])
				minimal["as_markdown"] = b.get("as_markdown", "")
			if t == "paragraph_chunk":
				minimal["text"] = b.get("text", "")
				minimal["chunk_index"] = b.get("chunk_index", 0)
				minimal["chunk_total"] = b.get("chunk_total", 1)
			append_jsonl(self.blocks_path, minimal)

	def write_blocks_enriched(self, page_ctx: Dict[str, Any], blocks: Iterable[Dict[str, Any]]) -> None:
		for b in blocks:
			obj = dict(b)
			obj.setdefault("doc_id", page_ctx.get("doc_id"))
			obj.setdefault("url", page_ctx.get("url"))
			obj.setdefault("title", page_ctx.get("title", ""))
			obj.setdefault("lang", page_ctx.get("lang", ""))
			append_jsonl(self.blocks_path, obj)

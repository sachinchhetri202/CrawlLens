# CrawlLens — History storage with thread-safe writes
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import json
import os
import threading
from datetime import datetime
from typing import List, Dict, Any


class ScrapingHistory:
	"""Thread-safe append-only history persisted to JSON file."""

	def __init__(self, filename: str = "scraping_history.json") -> None:
		self.filename = filename
		self._lock = threading.Lock()
		self.history: List[Dict[str, Any]] = self._load_history()

	def _load_history(self) -> List[Dict[str, Any]]:
		try:
			if os.path.exists(self.filename):
				with open(self.filename, "r", encoding="utf-8") as f:
					return json.load(f)
		except Exception:
			return []
		return []

	def _save_history(self) -> None:
		with self._lock:
			with open(self.filename, "w", encoding="utf-8") as f:
				json.dump(self.history, f, indent=2, ensure_ascii=False)

	def add_entry(
		self,
		url: str,
		title: str,
		heading: str,
		content_length: int,
		images_count: int,
		links_count: int,
	) -> None:
		entry = {
			"timestamp": datetime.now().isoformat(),
			"url": url,
			"title": title,
			"heading": heading,
			"content_length": content_length,
			"images_count": images_count,
			"links_count": links_count,
		}
		with self._lock:
			self.history.append(entry)
			self._save_history()

	def get_history(self) -> List[Dict[str, Any]]:
		with self._lock:
			return list(self.history)

	def clear_history(self) -> None:
		with self._lock:
			self.history = []
			self._save_history()

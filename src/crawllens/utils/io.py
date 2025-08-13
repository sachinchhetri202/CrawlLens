# CrawlLens — IO helpers (directories, JSONL writing)
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import json
import os
import threading
from typing import Any


_dir_lock = threading.Lock()
_jsonl_lock = threading.Lock()


def ensure_dirs(*paths: str) -> None:
	with _dir_lock:
		for p in paths:
			os.makedirs(p, exist_ok=True)


def append_jsonl(path: str, obj: Any) -> None:
	with _jsonl_lock:
		with open(path, "a", encoding="utf-8") as f:
			f.write(json.dumps(obj, ensure_ascii=False) + "\n")

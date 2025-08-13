# CrawlLens — Logging configuration (rotating file + stdout)
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import logging
import logging.handlers
import os


def configure_logging(level: str = "INFO", log_dir: str = "logs") -> None:
	"""Configure root logger with a rotating file handler and stdout.

	The format is JSON-ready (single-line) and includes time, level, logger, and message.
	"""
	os.makedirs(log_dir, exist_ok=True)
	log_path = os.path.join(log_dir, "crawllens.log")

	fmt = (
		"%(asctime)s\t%(levelname)s\t%(name)s\t%(message)s"
	)

	root = logging.getLogger()
	root.setLevel(getattr(logging, level.upper(), logging.INFO))

	# Clear existing handlers in case of re-init
	for h in list(root.handlers):
		root.removeHandler(h)

	stream = logging.StreamHandler()
	stream.setFormatter(logging.Formatter(fmt))
	root.addHandler(stream)

	file_handler = logging.handlers.RotatingFileHandler(
		log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
	)
	file_handler.setFormatter(logging.Formatter(fmt))
	root.addHandler(file_handler)

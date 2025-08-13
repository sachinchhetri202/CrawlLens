# CrawlLens — CLI (Typer)
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import sys
import typer
from typing import List, Optional
from rich import print

from .config import settings, Settings
from .core.crawl import Crawler, CrawlOptions
from .logging_config import configure_logging

app = typer.Typer(add_completion=False, no_args_is_help=True)


@app.command()
def crawl(
	seed: List[str] = typer.Argument(..., help="Seed URL(s) to crawl"),
	depth: int = typer.Option(None, help="Crawl depth (overrides env)"),
	delay: float = typer.Option(None, help="Minimum delay per host (seconds)"),
	same_domain: bool = typer.Option(None, help="Constrain to same domain as seed"),
	same_site: bool = typer.Option(None, help="Constrain to same eTLD+1 as seed"),
	use_sitemaps: bool = typer.Option(None, help="Seed queue from robots sitemaps"),
	export_jsonl: bool = typer.Option(None, help="Write pages.jsonl"),
	export_blocks: bool = typer.Option(None, help="Write blocks.jsonl"),
	compact_blocks: bool = typer.Option(None, help="Compact block schema"),
	user_agent: Optional[str] = typer.Option(None, help="Override User-Agent"),
	data_dir: Optional[str] = typer.Option(None, help="Data output directory"),
	retries: Optional[int] = typer.Option(None, help="HTTP retry attempts"),
	backoff: Optional[float] = typer.Option(None, help="Retry backoff factor"),
	log_level: Optional[str] = typer.Option(None, help="Log level"),
):
	"""Crawl seed URL(s) politely and export datasets under data_dir."""
	cfg = Settings()
	ua = user_agent or cfg.user_agent
	out_dir = data_dir or cfg.data_dir
	configure_logging(level=log_level or cfg.log_level)
	crawler = Crawler(user_agent=ua, data_dir=out_dir, retries=retries or cfg.retries, backoff=backoff or cfg.backoff)
	opt = CrawlOptions(
		max_depth=depth if depth is not None else cfg.max_depth,
		min_delay=delay if delay is not None else cfg.min_delay,
		same_domain_only=same_domain if same_domain is not None else cfg.same_domain_only,
		same_site_only=same_site if same_site is not None else cfg.same_site_only,
		use_sitemaps=use_sitemaps if use_sitemaps is not None else cfg.use_sitemaps,
		export_jsonl=export_jsonl if export_jsonl is not None else cfg.export_jsonl,
		export_blocks=export_blocks if export_blocks is not None else cfg.export_blocks,
		compact_blocks=compact_blocks if compact_blocks is not None else cfg.compact_blocks,
	)
	for s in seed:
		print(f"[bold]Crawling:[/bold] {s}")
		res = crawler.crawl(s, opt)
		print({
			"pages": res.pages_count,
			"blocks": res.blocks_count,
			"tables": res.tables_count,
			"last_export": res.last_export_path,
			"sitemaps": len(res.sitemaps),
		})


@app.command("print-config")
def print_config():
	"""Print effective configuration from environment."""
	cfg = Settings()
	print(cfg.model_dump())


def main():
	app()


if __name__ == "__main__":
	main()

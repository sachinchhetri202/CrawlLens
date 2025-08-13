## CrawlLens

Polite, structured website crawler with a desktop GUI and a headless CLI. CrawlLens discovers pages (optionally via sitemaps), honors `robots.txt` and crawl delays, extracts clean page blocks (headings, paragraphs, lists, code, tables), and writes training-ready JSONL plus raw HTML snapshots.

- **Author:** Sachin Chhetri  
- **Year:** 2025  
- **License:** MIT

## Why CrawlLens?

- **Respectful & robust:** robots-aware, per-host pacing, retries, and safe content gating.
- **Structured output:** JSONL records at page & block level (plus chunked paragraphs).
- **Two ways to use:** Click-and-crawl GUI, or automation-friendly CLI.
- **Portable:** Python 3.9+, optional accelerators (`lxml`, `ttkbootstrap`).

## Features

- Depth-limited BFS crawl with **same-domain** and **same-site (eTLD+1)** options  
- **Sitemap** discovery and seeding
- **Link audit** (sampled HEAD requests)
- **Meta/SEO** insights (canonical, language, description)
- **Dataset exports:**  
  - `data/jsonl/pages.jsonl` – page-level records (outline, links, hashes)  
  - `data/jsonl/blocks.jsonl` – normalized blocks (headings/paragraphs/lists/code/tables)  
  - `data/html/<doc_id>.html` – page snapshots
- **De-duplication:** text SHA-1 index prevents repeat writes
- **History UI** with filter/search, CSV/JSON export

## Install

```bash
python -m pip install -U pip
# From PyPI (if published):
pip install crawllens
# With optional extras (GUI + speedups):
pip install "crawllens[all]"

# From source checkout:
pip install .
# With extras from source:
pip install .[all]
```

## CLI

```bash
crawllens crawl https://example.com \
  --depth 1 --delay 2.0 \
  --same-domain --use-sitemaps \
  --export-jsonl --export-blocks
```

- **--depth**: 0..3 typical for polite exploratory crawls
- **--delay**: minimum seconds between requests to the same host (robots.txt may increase this)
- **--same-domain / --same-site**: constrain scope
- **--use-sitemaps**: seed queue with robots sitemap URLs
- **--export-jsonl / --export-blocks**: write datasets under `data/`
- Also available: `--compact-blocks`, `--user-agent`, `--data-dir`, `--retries`, `--backoff`, `--log-level`

Print effective configuration:

```bash
crawllens print-config
```

## GUI

```bash
crawllens-gui
```

- Responsive UI via worker threads and a message queue
- Live stats and dataset counters
- One-click export of results and history

## Outputs

- `data/html/{doc_id}.html`: raw HTML
- `data/jsonl/pages.jsonl`: per-page JSON lines
- `data/jsonl/blocks.jsonl`: block-level JSON lines (compact schema optional)
- `data/index/hashes.txt`: text content SHA-1 index to avoid duplicates

## Configuration

- Environment variables via Pydantic settings
- CLI flags override environment defaults

## Ethics & Politeness

CrawlLens is designed to be respectful:

- Always checks robots.txt and honors `crawl-delay`, `Disallow`, and meta robots tags
- Uses per-host pacing with minimum delay
- Performs a `HEAD` gate for non-HTML and size limits
- Bounded BFS depth, careful sitemap usage, and small link audit samples

Please crawl responsibly, identify yourself via `user_agent`, and never overwhelm a site.

## License

MIT © 2025 Sachin Chhetri

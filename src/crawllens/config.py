# CrawlLens — Configuration via Pydantic BaseSettings
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
	"""Application settings with sane defaults.

	Environment variables are prefixed with CRAWLLENS_. CLI flags can override.
	"""

	model_config = SettingsConfigDict(env_prefix="CRAWLLENS_", env_file=".env", extra="ignore")

	user_agent: str = Field(default="CrawlLens/0.1 (+https://example.com)")
	min_delay: float = Field(default=2.0)
	max_depth: int = Field(default=1)
	same_domain_only: bool = Field(default=True)
	same_site_only: bool = Field(default=False)
	use_sitemaps: bool = Field(default=True)
	export_jsonl: bool = Field(default=True)
	export_blocks: bool = Field(default=True)
	compact_blocks: bool = Field(default=True)
	data_dir: str = Field(default="data")
	retries: int = Field(default=3)
	backoff: float = Field(default=0.5)
	log_level: str = Field(default="INFO")


settings = Settings()

import pytest
from crawllens.utils.urls import normalize_url, same_domain, same_site


def test_normalize_url_basic():
	u = "HTTP://Example.COM:80/a//b/?utm_source=x&x=1#frag"
	n = normalize_url(u)
	assert n == "http://example.com/a/b/?x=1"


def test_same_domain():
	assert same_domain("https://a.example.com/x", "https://a.example.com/y")
	assert not same_domain("https://a.example.com", "https://b.example.com")


def test_same_site():
	assert same_site("https://a.example.co.uk", "https://b.example.co.uk")

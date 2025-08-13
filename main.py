from bs4 import BeautifulSoup
import requests
from requests.exceptions import HTTPError, ConnectionError, RequestException, Timeout
import time
import threading
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
from urllib.robotparser import RobotFileParser
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from tkinter import font as tkfont
from tkinter import filedialog
from datetime import datetime, timezone
import json
import os
import queue
import re
import webbrowser
import csv
import xml.etree.ElementTree as ET
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import hashlib
from collections import deque
try:
    import tldextract  # Optional; for eTLD+1 support
except Exception:
    tldextract = None
try:
    import ttkbootstrap as tb  # Optional; app falls back to plain ttk if missing
except Exception:
    tb = None

class ScrapingHistory:
    def __init__(self, filename="scraping_history.json"):
        self.filename = filename
        self.history = self.load_history()
    
    def load_history(self):
        """Load scraping history from file"""
        try:
            if os.path.exists(self.filename):
                with open(self.filename, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception:
            pass
        return []
    
    def save_history(self):
        """Save scraping history to file"""
        try:
            with open(self.filename, 'w', encoding='utf-8') as f:
                json.dump(self.history, f, indent=2, ensure_ascii=False)
        except Exception:
            pass
    
    def add_entry(self, url, title, heading, content_length, images_count, links_count):
        """Add a new scraping entry to history"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'title': title,
            'heading': heading,
            'content_length': content_length,
            'images_count': images_count,
            'links_count': links_count
        }
        self.history.append(entry)
        self.save_history()
    
    def get_history(self):
        """Get all history entries"""
        return self.history
    
    def clear_history(self):
        """Clear all history"""
        self.history = []
        self.save_history()

class WebScraperGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CrawlLens - Web Scraper")
        self.root.geometry("1200x700")
        self.root.configure(bg='#f0f0f0')
        
        # Initialize history
        self.history = ScrapingHistory()
        
        # Networking/session
        self.session = self._build_session()
        # Per-host robots + delay cache
        self._robots_cache = {}
        self._host_last_request = {}
        # Dedupe index (text sha1)
        self._hash_index_file = os.path.join('data', 'index', 'hashes.txt')
        self._hash_index = self._load_hash_index()
        # Running dataset counts
        self.dataset_pages_count = 0
        self.dataset_blocks_count = 0
        self.dataset_tables_count = 0
        self.last_export_path = ''
        
        # Threading and UI messaging
        self.ui_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.estimate_stop_event = threading.Event()
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.last_sitemaps = []
        # Dataset toggles
        self.use_sitemaps_var = tk.BooleanVar(value=True)
        self.export_jsonl_on_finish_var = tk.BooleanVar(value=True)
        self.same_site_only_var = tk.BooleanVar(value=False)
        self.export_blocks_var = tk.BooleanVar(value=True)
        self.compact_blocks_var = tk.BooleanVar(value=True)
        
        # Configure style (ttkbootstrap if available)
        try:
            style = tb.Style() if tb else ttk.Style()
        except Exception:
            style = ttk.Style()
        
        self.setup_ui()
        
        # Start UI queue draining
        self.root.after(100, self._drain_ui_queue)
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="CrawlLens", 
                               font=tkfont.Font(size=24, weight='bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Menu bar
        self._build_menu()
        # Theme menu runtime switch

        # URL input section
        url_frame = ttk.LabelFrame(main_frame, text="Enter URL to Scrape", padding="10")
        url_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 20))
        url_frame.columnconfigure(1, weight=1)
        
        ttk.Label(url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.url_entry = ttk.Entry(url_frame, width=60, font=('Arial', 10))
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.url_entry.focus()
        
        # Bind Enter key to scrape button
        self.url_entry.bind('<Return>', lambda e: self.start_scraping())
        
        # Advanced options (collapsible)
        self.advanced_frame = ttk.LabelFrame(url_frame, text="Advanced options", padding="10")
        self.advanced_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Label(self.advanced_frame, text="Crawl depth:").grid(row=0, column=0, sticky=tk.W)
        self.depth_var = tk.IntVar(value=0)
        self.depth_spin = ttk.Spinbox(self.advanced_frame, from_=0, to=3, textvariable=self.depth_var, width=5)
        self.depth_spin.grid(row=0, column=1, padx=(5, 15))
        
        ttk.Label(self.advanced_frame, text="Min delay (s):").grid(row=0, column=2, sticky=tk.W)
        self.delay_var = tk.DoubleVar(value=2.0)
        self.delay_spin = ttk.Spinbox(self.advanced_frame, from_=0.0, to=10.0, increment=0.5, textvariable=self.delay_var, width=6)
        self.delay_spin.grid(row=0, column=3, padx=(5, 15))
        
        self.same_domain_var = tk.BooleanVar(value=True)
        self.same_domain_chk = ttk.Checkbutton(self.advanced_frame, text="Same domain only", variable=self.same_domain_var)
        self.same_domain_chk.grid(row=0, column=4, padx=(0, 15))
        
        self.check_links_var = tk.BooleanVar(value=False)
        self.check_links_chk = ttk.Checkbutton(self.advanced_frame, text="Check links", variable=self.check_links_var)
        self.check_links_chk.grid(row=0, column=5, padx=(0, 10))
        
        ttk.Label(self.advanced_frame, text="Link check limit:").grid(row=0, column=6, sticky=tk.W)
        self.link_limit_var = tk.IntVar(value=20)
        self.link_limit_spin = ttk.Spinbox(self.advanced_frame, from_=5, to=200, textvariable=self.link_limit_var, width=6)
        self.link_limit_spin.grid(row=0, column=7, padx=(5, 0))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 20))
        
        self.scrape_button = ttk.Button(button_frame, text="Start", 
                                        command=self.start_scraping)
        self.scrape_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.cancel_button = ttk.Button(button_frame, text="Cancel", 
                                        command=self.cancel_scraping)
        self.cancel_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", 
                                      command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_history_button = ttk.Button(button_frame, text="Clear History", 
                                             command=self.clear_history)
        self.clear_history_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_history_button = ttk.Button(button_frame, text="Export History", 
                                               command=self.export_history)
        self.export_history_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_results_button = ttk.Button(button_frame, text="Export Results", 
                                               command=self.export_results)
        self.export_results_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.quit_button = ttk.Button(button_frame, text="Quit", 
                                     command=self.root.quit)
        self.quit_button.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Results tab
        results_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(results_frame, text="Scraping Results")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Summary strip above log
        self._setup_results_summary(results_frame)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, 
                                                     font=('Consolas', 9), height=20)
        self.results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # History tab
        history_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(history_frame, text="Scraping History")
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(1, weight=1)
        
        # History treeview
        self.setup_history_treeview(history_frame)

        # Sitemaps tab
        sitemaps_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(sitemaps_frame, text="Sitemaps")
        self._setup_sitemaps_tab(sitemaps_frame)

        # Dataset tab
        dataset_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(dataset_frame, text="Dataset")
        self._setup_dataset_tab(dataset_frame)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to scrape")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, 
                              relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Load initial history
        self.refresh_history()

        # Configure URL tag for clickable links in results
        self.results_text.tag_configure('url', foreground='blue', underline=True)
        self.results_text.tag_bind('url', '<Button-1>', self._open_link)
        
        # Make results read-only but scrollable and selectable
        self._bind_readonly()

        # Global key bindings
        self.root.bind('<Escape>', lambda e: self.cancel_scraping())
        self.root.bind('<Control-l>', lambda e: (self.url_entry.focus_set(), 'break'))
        self.root.bind('<Control-L>', lambda e: (self.url_entry.focus_set(), 'break'))
        self.root.bind('<Control-e>', lambda e: (self.export_results(), 'break'))
        self.root.bind('<Control-E>', lambda e: (self.export_results(), 'break'))
        self.root.bind('<Delete>', lambda e: (self.clear_results(), 'break'))
        
    def setup_history_treeview(self, parent):
        """Setup the history treeview with columns"""
        # Filter toolbar
        toolbar = ttk.Frame(parent)
        toolbar.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 8))
        ttk.Label(toolbar, text="Filter:").pack(side=tk.LEFT)
        self.history_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(toolbar, textvariable=self.history_filter_var, width=40)
        filter_entry.pack(side=tk.LEFT, padx=(6, 6))
        filter_entry.bind('<KeyRelease>', lambda e: self.refresh_history())
        ttk.Button(toolbar, text="Clear", command=lambda: (self.history_filter_var.set(''), self.refresh_history())).pack(side=tk.LEFT)

        # Create treeview
        columns = ('Timestamp', 'URL', 'Title', 'Content Length', 'Images', 'Links')
        self.history_tree = ttk.Treeview(parent, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.history_tree.heading('Timestamp', text='Timestamp')
        self.history_tree.heading('URL', text='URL')
        self.history_tree.heading('Title', text='Title')
        self.history_tree.heading('Content Length', text='Content Length')
        self.history_tree.heading('Images', text='Images')
        self.history_tree.heading('Links', text='Links')
        
        # Set column widths
        self.history_tree.column('Timestamp', width=150)
        self.history_tree.column('URL', width=300)
        self.history_tree.column('Title', width=200)
        self.history_tree.column('Content Length', width=100)
        self.history_tree.column('Images', width=80)
        self.history_tree.column('Links', width=80)
        
        # Add scrollbar
        history_scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scrollbar.set)
        
        # Grid layout
        self.history_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        history_scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        
        # Bind double-click to show details
        self.history_tree.bind('<Double-1>', self.show_history_details)
        # Bind heading click for sorting
        for col in columns:
            self.history_tree.heading(col, text=col, command=lambda c=col: self._sort_history_by(c, False))
        
        # Configure grid weights
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        
    def refresh_history(self):
        """Refresh the history display"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Add history items
        filter_text = ''
        try:
            filter_text = (self.history_filter_var.get() if hasattr(self, 'history_filter_var') else '').strip().lower()
        except Exception:
            filter_text = ''
        for entry in reversed(self.history.get_history()):  # Show newest first
            if filter_text:
                if filter_text not in entry.get('url', '').lower() and filter_text not in entry.get('title', '').lower():
                    continue
            timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            title = entry['title'][:50] + '...' if len(entry['title']) > 50 else entry['title']
            url = entry['url'][:80] + '...' if len(entry['url']) > 80 else entry['url']
            
            self.history_tree.insert('', 'end', values=(
                timestamp,
                url,
                title,
                f"{entry['content_length']:,}",
                entry['images_count'],
                entry['links_count']
            ))
    
    def show_history_details(self, event):
        """Show detailed information for a selected history item"""
        selection = self.history_tree.selection()
        if not selection:
            return
        
        # Get the selected item
        item = self.history_tree.item(selection[0])
        values = item['values']
        
        # Find the corresponding history entry
        timestamp = datetime.strptime(values[0], '%Y-%m-%d %H:%M:%S').isoformat()
        url = values[1]
        
        # Find the entry in history
        entry = None
        for hist_entry in self.history.get_history():
            if (datetime.fromisoformat(hist_entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S') == values[0] and
                hist_entry['url'].startswith(url.split('...')[0])):
                entry = hist_entry
                break
        
        if entry:
            # Create detail window
            detail_window = tk.Toplevel(self.root)
            detail_window.title(f"Scraping Details - {entry['url']}")
            detail_window.geometry("600x400")
            
            # Detail text
            detail_text = scrolledtext.ScrolledText(detail_window, wrap=tk.WORD, font=('Consolas', 9))
            detail_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Format details
            details = f"""SCRAPING DETAILS
{'='*50}

Timestamp: {datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}
URL: {entry['url']}
Title: {entry['title']}
Main Heading: {entry['heading']}
Content Length: {entry['content_length']:,} characters
Images Found: {entry['images_count']}
Links Found: {entry['links_count']}

{'='*50}"""
            
            detail_text.insert(tk.END, details)
            detail_text.config(state=tk.DISABLED)
    
    def clear_history(self):
        """Clear all scraping history"""
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all scraping history?"):
            self.history.clear_history()
            self.refresh_history()
            self.status_var.set("History cleared")
        
    def start_scraping(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a URL")
            return
            
        if not url.startswith(('http://', 'https://')):
            messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
            return
        
        # Disable button and show progress
        self.scrape_button.config(state='disabled')
        self.cancel_button.config(state='normal')
        self.progress.start()
        self.status_var.set("Scraping in progress...")
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.stop_event.clear()
        
        # Start scraping in a separate thread to keep GUI responsive
        options = {
            'max_depth': max(0, int(self.depth_var.get() or 0)),
            'min_delay': max(0.0, float(self.delay_var.get() or 0.0)),
            'same_domain_only': bool(self.same_domain_var.get()),
            'check_links': bool(self.check_links_var.get()),
            'link_check_limit': max(1, int(self.link_limit_var.get() or 20)),
            'use_sitemaps': bool(self.use_sitemaps_var.get()),
            'export_jsonl': bool(self.export_jsonl_on_finish_var.get()),
            'same_site_only': bool(self.same_site_only_var.get()),
            'export_blocks': bool(self.export_blocks_var.get()),
        }
        thread = threading.Thread(target=self.scrape_website, args=(url, options))
        thread.daemon = True
        thread.start()
    
    def cancel_scraping(self):
        self.stop_event.set()
        self.status_var.set("Cancelling...")
        
    def scrape_website(self, url, options):
        try:
            self.log(f"Processing URL: {url}\n")
            self.log("="*60 + "\n")
            
            # Check robots.txt
            is_allowed, robots_delay, robots_url, sitemaps = self.check_robots_txt(url)
            self.last_sitemaps = sitemaps or []
            self.root.after(0, self.refresh_sitemaps_tab)
            
            if not is_allowed:
                self.log("ERROR: Scraping not allowed according to robots.txt!\n")
                return
            
            # Use robots.txt delay if higher than default
            base_delay = max(options.get('min_delay', 0.0), float(robots_delay or 0.0))
            
            # Depth-limited crawl (BFS)
            max_depth = int(options.get('max_depth', 0))
            same_domain_only = bool(options.get('same_domain_only', True))
            same_site_only = bool(options.get('same_site_only', False))
            check_links = bool(options.get('check_links', False))
            link_check_limit = int(options.get('link_check_limit', 20))
            
            base_netloc = urlparse(url).netloc
            base_site = self._etld_plus_one(base_netloc)
            seen = set()
            dq = deque()
            start_url = self._normalize_url(url)
            dq.append((start_url, 0))
            
            if sitemaps:
                self.log(f"Found {len(sitemaps)} sitemap entries in robots.txt\n")
                for sm in sitemaps[:3]:
                    self.log(f"  Sitemap: {sm}\n")
                self.log("\n")
                # Only seed from sitemaps when max_depth > 0
                if options.get('use_sitemaps', True) and max_depth > 0:
                    try:
                        sitemap_urls = self._discover_from_sitemaps(sitemaps, limit=500)
                        for su in sitemap_urls:
                            nsu = self._normalize_url(su)
                            if nsu not in seen:
                                if same_site_only and self._etld_plus_one(urlparse(nsu).netloc) != base_site:
                                    continue
                                if same_domain_only and urlparse(nsu).netloc != base_netloc:
                                    continue
                                # Treat sitemap URLs as depth 1 relative to the seed
                                dq.append((nsu, 1))
                    except Exception:
                        pass
            
            while dq and not self.stop_event.is_set():
                current_url, depth = dq.popleft()
                if current_url in seen:
                    continue
                seen.add(current_url)
                
                # Respect robots per-URL
                if not self._can_fetch(current_url):
                    self.log(f"Skipping disallowed by robots: {current_url}\n")
                    continue
                
                # Scrape current page
                page_links = self.scrape_with_delay(current_url, base_delay, check_links, link_check_limit, export_jsonl=options.get('export_jsonl', True), export_blocks=options.get('export_blocks', True))
                
                if depth < max_depth and page_links:
                    for link in page_links:
                        if self.stop_event.is_set():
                            break
                        try:
                            if same_site_only and self._etld_plus_one(urlparse(link).netloc) != base_site:
                                continue
                            if same_domain_only and urlparse(link).netloc != base_netloc:
                                continue
                            if link not in seen:
                                dq.append((link, depth + 1))
                        except Exception:
                            continue
            
        except Exception as e:
            self.log(f"ERROR: An error occurred: {e}\n")
        finally:
            # Re-enable button and stop progress
            self.root.after(0, self.scraping_finished)
    
    def scraping_finished(self):
        self.scrape_button.config(state='normal')
        self.cancel_button.config(state='disabled')
        self.progress.stop()
        self.status_var.set("Scraping completed")
        self.results_text.see(tk.END)
        # Refresh history display
        self.refresh_history()
    
    def check_robots_txt(self, base_url):
        """Check robots.txt with a single network fetch, extract crawl-delay and sitemaps."""
        try:
            parsed_url = urlparse(base_url)
            robots_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", "/robots.txt")
            rp = RobotFileParser()
            sitemaps = []
            resp = self.session.get(robots_url, timeout=10)
            resp.raise_for_status()
            lines = resp.text.splitlines()
            for line in lines:
                if line.lower().startswith('sitemap:'):
                    try:
                        sm = line.split(':', 1)[1].strip()
                        if sm:
                            sitemaps.append(sm)
                    except Exception:
                        pass
            rp.parse(lines)
            user_agent = self.session.headers.get("User-Agent", "*")
            is_allowed = rp.can_fetch(user_agent, base_url)
            delay = rp.crawl_delay(user_agent)
            if delay is None:
                delay = 1
            # cache
            try:
                self._robots_cache[urlparse(base_url).netloc] = (rp, float(delay))
            except Exception:
                pass
            return is_allowed, delay, robots_url, sitemaps
        except Exception:
            # If robots.txt fails, assume scraping is allowed but be conservative
            return True, 2, None, []
    
    def scrape_with_delay(self, url, delay_seconds, check_links=False, link_check_limit=20, export_jsonl=True, export_blocks=True):
        """Scrape one HTML page with politeness. Returns normalized internal links for BFS."""
        if self.stop_event.is_set():
            return []
        try:
            # Respect per-host rate limit
            try:
                host = urlparse(url).netloc
                host_delay = max(float(delay_seconds or 0.0), float(self._robots_cache.get(host, (None, 0))[1] or 0.0))
                self._respect_rate_limit(host, host_delay)
            except Exception:
                pass
            
            # HEAD to check content-type
            try:
                head = self.session.head(url, allow_redirects=True, timeout=10)
                content_type = head.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    self.log(f"Skipping non-HTML content: {content_type} at {url}\n")
                    return []
            except Exception:
                # Some servers don't support HEAD; continue
                pass
            
            start = time.perf_counter()
            response = self.session.get(url, timeout=15)
            response.raise_for_status()
            elapsed = time.perf_counter() - start
            # re-check Content-Type after GET
            try:
                ctype = response.headers.get('Content-Type', '')
                if 'text/html' not in ctype:
                    self.log(f"Skipping non-HTML content after GET: {ctype} at {url}\n")
                    return []
            except Exception:
                pass
            # size gate 3 MB
            try:
                if len(response.content) > 3 * 1024 * 1024:
                    self.log(f"Skipping >3MB page: {url}\n")
                    return []
            except Exception:
                pass
            
            # Parse the HTML content
            soup = BeautifulSoup(response.content, 'html.parser')
            # meta robots handling
            meta_robots = ''
            try:
                mr = soup.find('meta', attrs={'name': re.compile(r'^robots$', re.I)})
                if mr:
                    meta_robots = (mr.get('content') or '').lower()
            except Exception:
                meta_robots = ''
            noindex = ('noindex' in meta_robots)
            nofollow = ('nofollow' in meta_robots)
            
            # Extract and display content
            internal_links, external_links = self.display_page_info(soup, url, elapsed, check_links=check_links, link_check_limit=link_check_limit)
            
            # Dataset extraction and export if allowed
            if export_jsonl and not noindex:
                try:
                    self._ensure_data_dirs()
                    # honor X-Robots-Tag: noindex
                    try:
                        xrobots = (response.headers.get('X-Robots-Tag','') or '').lower()
                        if 'noindex' in xrobots:
                            # skip exporting
                            page_record = None
                        else:
                            page_record, blocks, normalized_internal_links = self._extract_structured_page(url, response, soup)
                    except Exception:
                        page_record, blocks, normalized_internal_links = self._extract_structured_page(url, response, soup)

                    if not page_record:
                        normalized_internal_links = [self._normalize_url(l) for l in internal_links]
                    # dedupe by text_sha1
                    text_sha1_val = ''
                    try:
                        text_sha1_val = page_record.get('hashes',{}).get('text_sha1','')
                    except Exception:
                        text_sha1_val = ''
                    if page_record and text_sha1_val and text_sha1_val in self._hash_index:
                        pass
                    else:
                        if page_record and text_sha1_val:
                            self._append_hash(text_sha1_val)
                        # write raw html
                        try:
                            if page_record and page_record.get('doc_id'):
                                html_path = os.path.join('data', 'html', f"{page_record['doc_id']}.html")
                                with open(html_path, 'wb') as f:
                                    f.write(response.content)
                                self.last_export_path = html_path
                        except Exception:
                            pass
                        # write page jsonl (with blocks embedded)
                        try:
                            self.write_page_record(page_record)
                            self.dataset_pages_count += 1
                        except Exception:
                            pass
                        # write blocks jsonl
                        if export_blocks and blocks:
                            try:
                                self.write_block_records({'doc_id': page_record['doc_id'], 'url': page_record['url'], 'title': page_record.get('title',''), 'lang': page_record.get('lang','')}, blocks, compact=bool(self.compact_blocks_var.get()))
                                self.dataset_blocks_count += len(blocks)
                                self.dataset_tables_count += sum(1 for b in blocks if b.get('type') == 'table')
                            except Exception:
                                pass
                        # update dataset tab
                        self.root.after(0, self._refresh_dataset_tab)
                    # For BFS, prefer normalized links
                    if normalized_internal_links:
                        internal_links = normalized_internal_links
                except Exception:
                    pass
            
            # Rate limiting
            if delay_seconds and delay_seconds > 0:
                slept = 0.0
                while slept < delay_seconds and not self.stop_event.is_set():
                    time.sleep(0.1)
                    slept += 0.1
            
            # Honor nofollow by not returning links for crawl
            return [] if nofollow else [self._normalize_url(l) for l in internal_links]
            
        except HTTPError as http_err:
            self.log(f"HTTP error occurred: {http_err}\n")
        except ConnectionError as conn_err:
            self.log(f"Connection error occurred: {conn_err}\n")
        except Timeout as timeout_err:
            self.log(f"Request timed out: {timeout_err}\n")
        except Exception as e:
            self.log(f"An unexpected error occurred: {e}\n")
        return []
    
    def display_page_info(self, soup, url, elapsed_seconds=0.0, check_links=False, link_check_limit=20):
        """Display the extracted page information and save to history. Returns (internal_links, external_links)."""
        # Extract information
        title = soup.find('title')
        title_text = title.text.strip() if title else "No title"
        
        h1_element = soup.find('h1')
        heading_text = h1_element.text.strip() if h1_element else "No heading"
        
        main_content = soup.find('body')
        content_length = 0
        if main_content:
            text_content = main_content.get_text(separator=' ', strip=True)
            text_content = ' '.join(text_content.split())
            content_length = len(text_content)
        
        images = soup.find_all('img')
        images_count = len(images)
        
        links = soup.find_all('a', href=True)
        external_links = []
        internal_links = []
        base = url
        for link in links:
            href = link.get('href', '')
            if not href:
                continue
            resolved = urljoin(base, href)
            resolved = self._normalize_url(resolved)
            if not resolved.startswith(('http://', 'https://')):
                continue
            if urlparse(resolved).netloc != urlparse(url).netloc:
                external_links.append(resolved)
            else:
                internal_links.append(resolved)
        links_count = len(external_links) + len(internal_links)
        
        # Meta/SEO insights
        description = ''
        meta_desc = soup.find('meta', attrs={'name': 'description'}) or soup.find('meta', attrs={'property': 'og:description'})
        if meta_desc:
            description = meta_desc.get('content', '').strip()
        canonical = ''
        link_canonical = soup.find('link', rel=lambda v: v and 'canonical' in v)
        if link_canonical:
            canonical = link_canonical.get('href', '').strip()
        html_tag = soup.find('html')
        lang = html_tag.get('lang', '').strip() if html_tag and html_tag.has_attr('lang') else ''
        word_count = len((main_content.get_text(" ", strip=True) if main_content else '').split())
        heading_counts = {f"h{i}": len(soup.find_all(f'h{i}')) for i in range(1, 7)}
        images_with_alt = sum(1 for img in images if img.get('alt'))
        alt_coverage = (images_with_alt / images_count * 100.0) if images_count else 0.0
        
        # Save to history
        self.history.add_entry(url, title_text, heading_text, content_length, images_count, links_count)
        
        # Display information
        self.log(f"Page Title: {title_text}\n\n")
        self.log(f"Main Heading: {heading_text}\n\n")
        self.log(f"Total Content Length: {content_length:,} characters\n\n")
        if elapsed_seconds:
            self.log(f"Fetched in: {elapsed_seconds:.2f}s\n\n")
        
        # Page Statistics
        self.log("PAGE STATISTICS:\n")
        self.log(f"   Headings (H1-H6): {len(soup.find_all(['h1', 'h2', 'h3', 'h4', 'h5', 'h6']))}\n")
        self.log(f"   Paragraphs: {len(soup.find_all('p'))}\n")
        self.log(f"   Lists: {len(soup.find_all(['ul', 'ol']))}\n")
        self.log(f"   Tables: {len(soup.find_all('table'))}\n\n")
        
        # SEO Insights
        self.log("SEO INSIGHTS:\n")
        self.log(f"   Meta Description: {description[:120]}{'...' if len(description) > 120 else ''}\n")
        self.log(f"   Canonical URL: {canonical or 'N/A'}\n")
        self.log(f"   Language: {lang or 'N/A'}\n")
        self.log(f"   Word Count: {word_count}\n")
        self.log("   Heading counts: " + ", ".join([f"{k.upper()}={v}" for k, v in heading_counts.items()]) + "\n")
        self.log(f"   Image alt coverage: {alt_coverage:.1f}%\n\n")
        
        # Images Found
        if images:
            self.log(f"IMAGES FOUND: {images_count}\n")
            for i, img in enumerate(images[:5]):
                src = img.get('src', 'No source')
                alt = img.get('alt', 'No alt text')
                self.log(f"   {i+1}. {alt[:40]}{'...' if len(alt) > 40 else ''}\n")
                self.log(f"      Source: {src}\n")
            self.log("\n")
        
        # Links Found
        self.log("LINKS FOUND:\n")
        self.log(f"   Internal Links: {len(internal_links)}\n")
        self.log(f"   External Links: {len(external_links)}\n")
        
        # Optional broken link audit
        if check_links and (internal_links or external_links):
            self.log("\nBROKEN LINK AUDIT (HEAD requests):\n")
            audit_sample = (internal_links + external_links)[:max(1, int(link_check_limit))]
            status_buckets = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "error": 0}
            for link_url in audit_sample:
                if self.stop_event.is_set():
                    break
                try:
                    r = self.session.head(link_url, allow_redirects=True, timeout=8)
                    code = r.status_code
                    if 200 <= code < 300:
                        status_buckets["2xx"] += 1
                    elif 300 <= code < 400:
                        status_buckets["3xx"] += 1
                    elif 400 <= code < 500:
                        status_buckets["4xx"] += 1
                    elif 500 <= code < 600:
                        status_buckets["5xx"] += 1
                    else:
                        status_buckets["error"] += 1
                except Exception:
                    status_buckets["error"] += 1
            audit_str = ", ".join([f"{k}={v}" for k, v in status_buckets.items()])
            self.log("   Status distribution: " + audit_str + "\n")
        else:
            audit_str = "disabled"
        
        self.log("\n" + "="*60 + "\n")
        
        # Update summary strip
        try:
            self.summary_title_var.set(title_text[:80])
            self.summary_fetch_var.set(f"{elapsed_seconds:.2f}s" if elapsed_seconds else "-")
            self.summary_content_var.set(f"{content_length:,}")
            self.summary_wordcount_var.set(str(word_count))
            self.summary_links_var.set(f"int {len(internal_links)} / ext {len(external_links)}")
            self.summary_meta_var.set("Yes" if description else "No")
            self.summary_canonical_var.set(canonical or "-")
            self.summary_lang_var.set(lang or "-")
            self.summary_headings_var.set(
                ", ".join([f"H{i}={heading_counts[f'h{i}']}" for i in range(1,7)])
            )
            self.summary_alt_var.set(f"{alt_coverage:.1f}%")
            self.summary_audit_var.set(audit_str)
        except Exception:
            pass

        return internal_links, external_links
    
    def clear_results(self):
        """Clear the results text area"""
        self.results_text.delete(1.0, tk.END)
        self.status_var.set("Results cleared")

    # ------------- Helpers: networking, robots, UI logging, sorting, exports, links -------------
    def _build_session(self, user_agent="WebScraperGUI/1.0"):
        s = requests.Session()
        s.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        })
        retry = Retry(total=3, backoff_factor=0.5,
                      status_forcelist=(429, 500, 502, 503, 504),
                      allowed_methods=("GET", "HEAD"))
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    # ---------------- Dataset helpers ----------------
    def _ensure_data_dirs(self):
        try:
            os.makedirs(os.path.join('data', 'html'), exist_ok=True)
            os.makedirs(os.path.join('data', 'jsonl'), exist_ok=True)
            os.makedirs(os.path.join('data', 'index'), exist_ok=True)
        except Exception:
            pass

    def _load_hash_index(self):
        index = set()
        try:
            path = self._hash_index_file
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8') as f:
                    for line in f:
                        h = line.strip()
                        if h:
                            index.add(h)
        except Exception:
            return set()
        return index

    def _append_hash(self, sha1_hex):
        try:
            self._hash_index.add(sha1_hex)
            with open(self._hash_index_file, 'a', encoding='utf-8') as f:
                f.write(sha1_hex + "\n")
        except Exception:
            pass

    def _write_jsonl(self, path, obj):
        try:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def write_page_record(self, page_obj):
        try:
            self._write_jsonl(os.path.join('data', 'jsonl', 'pages.jsonl'), page_obj)
        except Exception:
            pass

    def write_block_records(self, page_ctx, blocks, compact=True):
        try:
            path = os.path.join('data', 'jsonl', 'blocks.jsonl')
            for b in blocks:
                if compact:
                    # Minimal training schema per block type
                    minimal = {
                        'doc_id': page_ctx.get('doc_id'),
                        'url': page_ctx.get('url'),
                        'title': page_ctx.get('title',''),
                        'lang': page_ctx.get('lang',''),
                        'block_id': b.get('block_id',''),
                        'type': b.get('type'),
                        'section_id': b.get('section_id',''),
                    }
                    t = b.get('type')
                    if t == 'paragraph':
                        minimal['text'] = b.get('text','')
                    elif t == 'heading':
                        minimal['text'] = b.get('text','')
                        minimal['level'] = b.get('level')
                    elif t == 'list':
                        minimal['items'] = b.get('items',[])
                        minimal['as_text'] = b.get('as_text','')
                    elif t == 'code':
                        minimal['raw'] = b.get('raw','')
                        minimal['language'] = b.get('language','')
                        minimal['text'] = b.get('text','')
                    elif t == 'table':
                        minimal['caption'] = b.get('caption','')
                        minimal['headers'] = b.get('headers',[])
                        minimal['rows'] = b.get('rows',[])
                        minimal['as_markdown'] = b.get('as_markdown','')
                    elif t == 'paragraph_chunk':
                        minimal['text'] = b.get('text','')
                        minimal['chunk_index'] = b.get('chunk_index',0)
                        minimal['chunk_total'] = b.get('chunk_total',1)
                    # Omit heavy UI/DOM fields for training: dom_path, section_path
                    self._write_jsonl(path, minimal)
                else:
                    enriched = dict(b)
                    enriched.setdefault('doc_id', page_ctx.get('doc_id'))
                    enriched.setdefault('url', page_ctx.get('url'))
                    enriched.setdefault('title', page_ctx.get('title',''))
                    enriched.setdefault('lang', page_ctx.get('lang',''))
                    self._write_jsonl(path, enriched)
        except Exception:
            pass

    def _normalize_url(self, url):
        try:
            parsed = urlparse(url)
            # remove fragments
            fragmentless = parsed._replace(fragment='')
            # strip tracking params
            query_pairs = [(k, v) for k, v in parse_qsl(fragmentless.query, keep_blank_values=False)
                           if k.lower() not in ("utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid")]
            new_query = urlencode(query_pairs, doseq=True)
            # lower scheme/host
            netloc = fragmentless.netloc.lower()
            scheme = fragmentless.scheme.lower() if fragmentless.scheme else 'https'
            cleaned = fragmentless._replace(query=new_query, netloc=netloc, scheme=scheme)
            # handle default ports
            if cleaned.netloc.endswith(':80') and cleaned.scheme == 'http':
                cleaned = cleaned._replace(netloc=cleaned.netloc[:-3])
            if cleaned.netloc.endswith(':443') and cleaned.scheme == 'https':
                cleaned = cleaned._replace(netloc=cleaned.netloc[:-4])
            # remove duplicate slashes in path
            path = re.sub(r"/+", "/", cleaned.path or "/")
            cleaned = cleaned._replace(path=path)
            return urlunparse(cleaned)
        except Exception:
            return url

    def _etld_plus_one(self, netloc):
        try:
            if not tldextract:
                return netloc
            ext = tldextract.extract(netloc)
            return ".".join([p for p in [ext.domain, ext.suffix] if p])
        except Exception:
            return netloc

    def _respect_rate_limit(self, host, delay_seconds):
        try:
            now = time.monotonic()
            last = self._host_last_request.get(host)
            if last is not None and delay_seconds and delay_seconds > 0:
                elapsed = now - last
                remaining = delay_seconds - elapsed
                if remaining > 0:
                    slept = 0.0
                    while slept < remaining and not self.stop_event.is_set():
                        time.sleep(0.1)
                        slept += 0.1
            self._host_last_request[host] = time.monotonic()
        except Exception:
            pass

    def _discover_from_sitemaps(self, sitemap_urls, limit=1000):
        discovered = []
        for sm in sitemap_urls:
            if self.stop_event.is_set():
                break
            try:
                r = self.session.get(sm, timeout=12)
                r.raise_for_status()
                text = r.text
                # simple XML parse: urlset or sitemapindex
                root = ET.fromstring(text)
                ns = ''
                if root.tag.endswith('urlset'):
                    for url_el in root.findall('.//{*}loc'):
                        if len(discovered) >= limit:
                            break
                        loc = (url_el.text or '').strip()
                        if loc:
                            discovered.append(loc)
                elif root.tag.endswith('sitemapindex'):
                    for sm_el in root.findall('.//{*}loc'):
                        loc = (sm_el.text or '').strip()
                        if not loc:
                            continue
                        try:
                            rr = self.session.get(loc, timeout=12)
                            rr.raise_for_status()
                            rr_root = ET.fromstring(rr.text)
                            for url_el in rr_root.findall('.//{*}loc'):
                                if len(discovered) >= limit:
                                    break
                                loc2 = (url_el.text or '').strip()
                                if loc2:
                                    discovered.append(loc2)
                        except Exception:
                            continue
            except Exception:
                continue
        return discovered

    # ---------------- Structured extraction ----------------
    def _extract_structured_page(self, url, response, soup):
        # canonical and effective URL
        canonical_url = ''
        try:
            link_canonical = soup.find('link', rel=lambda v: v and 'canonical' in v)
            if link_canonical:
                canonical_url = self._normalize_url(link_canonical.get('href', '').strip())
        except Exception:
            canonical_url = ''
        effective_url = canonical_url or self._normalize_url(response.url or url)

        # remove boilerplate
        try:
            boilerplate = r"nav|menu|header|footer|sidebar|cookie|newsletter|share|ads"
            for elem in list(soup.find_all(True, attrs={'id': True})):
                if re.search(boilerplate, elem.get('id', ''), re.I):
                    elem.decompose()
            for elem in list(soup.find_all(True, attrs={'class': True})):
                classes = " ".join(elem.get('class') or [])
                if re.search(boilerplate, classes, re.I):
                    elem.decompose()
        except Exception:
            pass

        title_el = soup.find('title')
        title_text = (title_el.get_text(strip=True) if title_el else '').strip()

        # outline and blocks
        outline, blocks = self.extract_outline_and_blocks(soup)

        # metadata
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

        # links
        internal_links, external_links = self._extract_links(soup, effective_url)

        # hashes and ids
        page_text_parts = []
        for b in blocks:
            if b['type'] == 'paragraph':
                page_text_parts.append(b.get('text',''))
            elif b['type'] == 'list':
                page_text_parts.extend(b.get('items', []))
            elif b['type'] == 'code':
                page_text_parts.append(b.get('text',''))
            elif b['type'] == 'table':
                page_text_parts.append(b.get('as_markdown',''))
            elif b['type'] == 'heading':
                page_text_parts.append(b.get('text',''))
        page_text = '\n\n'.join([p for p in page_text_parts if p])
        text_sha1 = hashlib.sha1(page_text.encode('utf-8', errors='ignore')).hexdigest() if page_text else hashlib.sha1((effective_url or '').encode('utf-8')).hexdigest()
        page_md5 = hashlib.md5((response.text or '').encode('utf-8', errors='ignore')).hexdigest()
        doc_id = hashlib.sha1((canonical_url or effective_url or url).encode('utf-8')).hexdigest()[:16]

        # paths
        source_html_path = os.path.join('data', 'html', f"{doc_id}.html")

        # page object per schema
        page_obj = {
            'doc_id': doc_id,
            'url': effective_url,
            'canonical_url': canonical_url or effective_url,
            'fetched_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'title': title_text,
            'lang': lang,
            'meta': {
                'description': meta_desc,
                'robots': robots_meta,
                'word_count': word_count,
                'heading_counts': heading_counts,
            },
            'outline': outline,
            'blocks': blocks,
            'links': {
                'internal': list({l for l in internal_links}),
                'external': list({l for l in external_links}),
            },
            'hashes': {
                'page_md5': page_md5,
                'text_sha1': text_sha1,
            },
            'source_html_path': source_html_path.replace('\\','/'),
        }

        # block-level JSONL records
        block_records = self._build_block_records_for_jsonl(page_obj)

        # normalized internal links to feed BFS
        norm_internal = [self._normalize_url(l) for l in internal_links]

        return page_obj, block_records, norm_internal

    def _extract_links(self, soup, base_url):
        internal_links = []
        external_links = []
        for a in soup.find_all('a', href=True):
            href = a.get('href', '')
            if not href:
                continue
            resolved = self._normalize_url(urljoin(base_url, href))
            if not resolved.startswith(('http://','https://')):
                continue
            if urlparse(resolved).netloc == urlparse(base_url).netloc:
                internal_links.append(resolved)
            else:
                external_links.append(resolved)
        return internal_links, external_links

    def _chunk_blocks_by_section(self, blocks):
        # Chunking now used for blocks.jsonl only via _build_block_records_for_jsonl
        return {'blocks': blocks}

    def css_dom_path(self, el):
        try:
            parts = []
            node = el
            # stop at html
            while node and getattr(node, 'name', None) and node.name != 'html':
                index = 1
                if node.parent:
                    index = 1 + len([s for s in node.parent.find_all(node.name, recursive=False) if s is not node and s.sourcepos and s.sourcepos < getattr(node, 'sourcepos', 0)])
                # Fallback index using previous_siblings count
                if index == 1:
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

    def list_to_struct(self, list_el):
        items = []
        for li in list_el.find_all('li', recursive=False):
            if self.stop_event.is_set():
                break
            itxt = ' '.join(li.get_text(' ', strip=True).split())
            if itxt:
                items.append(itxt)
        return {
            'items': items,
            'as_text': '\n'.join(['• ' + i for i in items])
        }

    def table_to_struct(self, table_el):
        caption = ''
        headers = []
        rows = []
        cap = table_el.find('caption')
        if cap:
            caption = ' '.join(cap.get_text(' ', strip=True).split())
        thead = table_el.find('thead')
        if thead:
            tr = thead.find('tr')
            if tr:
                for th in tr.find_all(['th','td']):
                    headers.append(' '.join(th.get_text(' ', strip=True).split()))
        if not headers:
            # infer from first row when all cells are th
            first_tr = table_el.find('tr')
            if first_tr:
                ths = first_tr.find_all('th')
                tds = first_tr.find_all('td')
                if ths and not tds:
                    headers = [' '.join(th.get_text(' ', strip=True).split()) for th in ths]
        for tr in table_el.find_all('tr'):
            cells = [' '.join(td.get_text(' ', strip=True).split()) for td in tr.find_all(['td','th'])]
            if cells:
                rows.append(cells)
        # markdown
        as_md = ''
        if headers:
            as_md += '| ' + ' | '.join(headers) + ' |\n'
            as_md += '| ' + ' | '.join(['---']*len(headers)) + ' |\n'
            # if first row was headers, skip it in rows for markdown body
            start_idx = 1 if rows and all(c in headers for c in rows[0]) else 1 if rows and len(rows[0]) == len(headers) else 0
            for r in rows[start_idx:]:
                as_md += '| ' + ' | '.join(r) + ' |\n'
        else:
            for r in rows:
                as_md += '| ' + ' | '.join(r) + ' |\n'
        return {
            'caption': caption,
            'headers': headers,
            'rows': rows,
            'as_markdown': as_md
        }

    def extract_outline_and_blocks(self, soup):
        body = soup.find('body') or soup
        # Build outline with stable ids like s1, s1.1, s1.2, s2, ...
        outline = []
        blocks = []
        section_counters = [0,0,0,0,0,0]
        last_section_id_for_level = ['','','','','','']

        def next_section_id(level):
            # level is 1..6
            idx = level - 1
            section_counters[idx] += 1
            for j in range(idx+1,6):
                section_counters[j] = 0
            parts = []
            for j in range(0, level):
                if section_counters[j] == 0:
                    continue
                parts.append(str(section_counters[j]))
            return 's' + '.'.join(parts)

        # Collect headings in order
        all_nodes = list(body.descendants)
        heading_tags = {f'h{i}' for i in range(1,7)}
        content_tags = heading_tags.union({'p','ul','ol','pre','code','table'})
        i = 0
        current_stack = []  # list of (level, section_id, text)

        def current_section_path():
            if not current_stack:
                return ''
            return ' > '.join([f"H{lvl}:{txt}" for (lvl, sid, txt) in current_stack])

        def nearest_section_id():
            if not current_stack:
                return ''
            return current_stack[-1][1]

        def add_heading_block(hnode, level, section_id, text):
            blocks.append({
                'block_id': '',
                'type': 'heading',
                'level': level,
                'section_id': section_id,
                'section_path': current_section_path(),
                'dom_path': self.css_dom_path(hnode),
                'text': text,
            })

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
                    # adjust stack
                    while current_stack and current_stack[-1][0] >= level:
                        current_stack.pop()
                    current_stack.append((level, sid, text))
                    outline.append({'id': sid, 'level': level, 'text': text})
                    add_heading_block(node, level, sid, text)
                except Exception:
                    continue
                continue
            # non-heading block, assign to nearest heading
            sect_id = nearest_section_id()
            sect_path = current_section_path()
            if node.name == 'p':
                text = ' '.join(node.get_text(' ', strip=True).split())
                if not text:
                    continue
                blocks.append({
                    'block_id': '',
                    'type': 'paragraph',
                    'section_id': sect_id,
                    'section_path': sect_path,
                    'dom_path': self.css_dom_path(node),
                    'text': text,
                })
            elif node.name in ('ul','ol'):
                lst = self.list_to_struct(node)
                if not lst.get('items'):
                    continue
                blocks.append({
                    'block_id': '',
                    'type': 'list',
                    'section_id': sect_id,
                    'section_path': sect_path,
                    'dom_path': self.css_dom_path(node),
                    'text': lst.get('as_text',''),
                    'items': lst.get('items',[]),
                    'as_text': lst.get('as_text',''),
                })
            elif node.name in ('pre','code'):
                raw = node.get_text('\n', strip=False)
                text = ' '.join(raw.split())
                blocks.append({
                    'block_id': '',
                    'type': 'code',
                    'section_id': sect_id,
                    'section_path': sect_path,
                    'dom_path': self.css_dom_path(node),
                    'text': text,
                    'language': '',
                    'raw': raw,
                })
            elif node.name == 'table':
                tbl = self.table_to_struct(node)
                blocks.append({
                    'block_id': '',
                    'type': 'table',
                    'section_id': sect_id,
                    'section_path': sect_path,
                    'dom_path': self.css_dom_path(node),
                    'caption': tbl.get('caption',''),
                    'headers': tbl.get('headers',[]),
                    'rows': tbl.get('rows',[]),
                    'as_markdown': tbl.get('as_markdown',''),
                })
        # assign sequential block_ids b1..bn
        for idx, b in enumerate(blocks, start=1):
            b['block_id'] = f"b{idx}"
        return outline, blocks

    def _build_block_records_for_jsonl(self, page_obj):
        # Build block records enriched with page context and add paragraph_chunk virtual blocks when needed
        MAX_TOKENS_PER_CHUNK = 1500
        OVERLAP_TOKENS = 150
        def est_tokens(text):
            return max(1, int(len(text) / 4))

        records = []
        for b in page_obj.get('blocks', []):
            rec = {
                'doc_id': page_obj['doc_id'],
                'url': page_obj['url'],
                'title': page_obj.get('title',''),
                'lang': page_obj.get('lang',''),
                'block_id': b.get('block_id',''),
                'type': b.get('type'),
                'section_id': b.get('section_id',''),
                'section_path': b.get('section_path',''),
                'dom_path': b.get('dom_path',''),
            }
            # merge type-specific
            for key in ('text','items','as_text','level','language','raw','caption','headers','rows','as_markdown'):
                if key in b:
                    rec[key] = b[key]
            records.append(rec)
            # paragraph chunking virtual blocks
            if b.get('type') == 'paragraph':
                text = b.get('text','')
                if est_tokens(text) > MAX_TOKENS_PER_CHUNK:
                    # split by sentences/paragraph boundaries (simple split by '. ' as fallback)
                    parts = re.split(r"\n\n+|(?<=[.!?])\s+", text)
                    chunks = []
                    current = []
                    current_tokens = 0
                    for part in parts:
                        pt = est_tokens(part)
                        if current_tokens + pt > MAX_TOKENS_PER_CHUNK and current:
                            chunks.append(' '.join(current))
                            # overlap
                            overlap_tokens = 0
                            overlap = []
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
                            'doc_id': page_obj['doc_id'],
                            'url': page_obj['url'],
                            'title': page_obj.get('title',''),
                            'lang': page_obj.get('lang',''),
                            'block_id': f"{b.get('block_id','')}-c{idx+1}",
                            'type': 'paragraph_chunk',
                            'section_id': b.get('section_id',''),
                            'section_path': b.get('section_path',''),
                            'dom_path': b.get('dom_path',''),
                            'text': ch,
                            'chunk_index': idx,
                            'chunk_total': total,
                        })
        return records

    def _can_fetch(self, url):
        try:
            parsed_url = urlparse(url)
            robots_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", "/robots.txt")
            rp = RobotFileParser()
            try:
                resp = self.session.get(robots_url, timeout=6)
                resp.raise_for_status()
                rp.parse(resp.text.splitlines())
            except Exception:
                return True
            return rp.can_fetch(self.session.headers.get("User-Agent", "*"), url)
        except Exception:
            return True

    def log(self, text):
        try:
            self.ui_queue.put_nowait(text)
        except Exception:
            pass

    def _drain_ui_queue(self):
        try:
            while True:
                text = self.ui_queue.get_nowait()
                try:
                    yfirst, ylast = self.results_text.yview()
                    near_bottom = (ylast >= 0.999)
                except Exception:
                    near_bottom = True
                self._insert_with_links(text)
                if self.autoscroll_var.get() and near_bottom:
                    self.results_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_ui_queue)

    def _insert_with_links(self, text):
        url_pattern = re.compile(r"https?://[^\s)]+")
        idx = 0
        for m in url_pattern.finditer(text):
            start, end = m.span()
            if start > idx:
                self.results_text.insert(tk.END, text[idx:start])
            url_text = text[start:end]
            start_index = self.results_text.index(tk.INSERT)
            self.results_text.insert(tk.END, url_text)
            end_index = self.results_text.index(tk.INSERT)
            self.results_text.tag_add('url', start_index, end_index)
            idx = end
        if idx < len(text):
            self.results_text.insert(tk.END, text[idx:])

    def _open_link(self, event):
        try:
            index = self.results_text.index("@%s,%s" % (event.x, event.y))
            ranges = self.results_text.tag_prevrange('url', index)
            if not ranges:
                return
            start, end = ranges
            url_text = self.results_text.get(start, end)
            if url_text:
                webbrowser.open(url_text)
        except Exception:
            pass

    def _bind_readonly(self):
        try:
            text = self.results_text
            # Block edits
            for seq in ("<Key>", "<BackSpace>", "<Delete>", "<Return>", "<Tab>", "<<Paste>>", "<<Cut>>", "<Control-v>", "<Control-V>"):
                text.bind(seq, lambda e: "break")
            # Allow copy
            for seq in ("<Control-c>", "<Control-C>"):
                text.bind(seq, lambda e: None)
        except Exception:
            pass

    # ------------- UI builders for summary, sitemaps, and menu -------------
    def _setup_results_summary(self, parent):
        wrap = ttk.Frame(parent)
        wrap.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 8))
        for i in range(0, 6):
            wrap.columnconfigure(i, weight=1)
        # Variables
        self.summary_title_var = tk.StringVar(value='—')
        self.summary_fetch_var = tk.StringVar(value='—')
        self.summary_content_var = tk.StringVar(value='—')
        self.summary_wordcount_var = tk.StringVar(value='—')
        self.summary_links_var = tk.StringVar(value='—')
        self.summary_meta_var = tk.StringVar(value='—')
        self.summary_canonical_var = tk.StringVar(value='—')
        self.summary_lang_var = tk.StringVar(value='—')
        self.summary_headings_var = tk.StringVar(value='—')
        self.summary_alt_var = tk.StringVar(value='—')
        self.summary_audit_var = tk.StringVar(value='—')
        # Row 0
        ttk.Label(wrap, text="Title:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_title_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(wrap, text="Fetched:").grid(row=0, column=2, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_fetch_var).grid(row=0, column=3, sticky=tk.W)
        ttk.Label(wrap, text="Content:").grid(row=0, column=4, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_content_var).grid(row=0, column=5, sticky=tk.W)
        # Row 1
        ttk.Label(wrap, text="Words:").grid(row=1, column=0, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_wordcount_var).grid(row=1, column=1, sticky=tk.W)
        ttk.Label(wrap, text="Links:").grid(row=1, column=2, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_links_var).grid(row=1, column=3, sticky=tk.W)
        ttk.Label(wrap, text="Meta desc:").grid(row=1, column=4, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_meta_var).grid(row=1, column=5, sticky=tk.W)
        # Row 2
        ttk.Label(wrap, text="Canonical:").grid(row=2, column=0, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_canonical_var).grid(row=2, column=1, sticky=tk.W)
        ttk.Label(wrap, text="Lang:").grid(row=2, column=2, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_lang_var).grid(row=2, column=3, sticky=tk.W)
        ttk.Label(wrap, text="Alt coverage:").grid(row=2, column=4, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_alt_var).grid(row=2, column=5, sticky=tk.W)
        # Row 3
        ttk.Label(wrap, text="Headings:").grid(row=3, column=0, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_headings_var).grid(row=3, column=1, columnspan=3, sticky=tk.W)
        ttk.Label(wrap, text="Link audit:").grid(row=3, column=4, sticky=tk.W)
        ttk.Label(wrap, textvariable=self.summary_audit_var).grid(row=3, column=5, sticky=tk.W)

    def _setup_sitemaps_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        ttk.Label(parent, text="Sitemap URLs discovered from robots.txt").grid(row=0, column=0, sticky=tk.W, pady=(0, 6))
        frame = ttk.Frame(parent)
        frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        frame.columnconfigure(0, weight=1)
        self.sitemaps_list = tk.Listbox(frame, height=10)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.sitemaps_list.yview)
        self.sitemaps_list.configure(yscrollcommand=vsb.set)
        self.sitemaps_list.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.sitemaps_list.bind('<Double-1>', lambda e: self._open_selected_sitemap())
        btns = ttk.Frame(parent)
        btns.grid(row=2, column=0, sticky=tk.E, pady=(6,0))
        ttk.Button(btns, text="Open", command=self._open_selected_sitemap).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Refresh", command=self.refresh_sitemaps_tab).pack(side=tk.RIGHT, padx=(0,6))

    def refresh_sitemaps_tab(self):
        try:
            self.sitemaps_list.delete(0, tk.END)
            for sm in self.last_sitemaps:
                self.sitemaps_list.insert(tk.END, sm)
        except Exception:
            pass

    def _open_selected_sitemap(self):
        try:
            sel = self.sitemaps_list.curselection()
            if not sel:
                return
            url = self.sitemaps_list.get(sel[0])
            webbrowser.open(url)
        except Exception:
            pass

    def _build_menu(self):
        menubar = tk.Menu(self.root)
        # File
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Results", command=self.export_results)
        file_menu.add_command(label="Export History", command=self.export_history)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        # View
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_checkbutton(label="Auto-scroll", onvalue=True, offvalue=False, variable=self.autoscroll_var)
        view_menu.add_command(label="Toggle Advanced options", command=self._toggle_advanced)
        # Theme submenu
        theme_menu = tk.Menu(view_menu, tearoff=0)
        for name in ("flatly", "darkly", "cosmo", "litera", "minty", "sandstone", "cyborg"):
            theme_menu.add_command(label=name, command=lambda n=name: self._set_theme(n))
        view_menu.add_cascade(label="Theme", menu=theme_menu)
        menubar.add_cascade(label="View", menu=view_menu)
        # Tools
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Re-scan Page", command=self.start_scraping)
        tools_menu.add_command(label="Open URL", command=lambda: webbrowser.open(self.url_entry.get().strip()) if self.url_entry.get().strip() else None)
        tools_menu.add_separator()
        tools_menu.add_command(label="Clear Output", command=self.clear_results)
        tools_menu.add_command(label="Clear History", command=self.clear_history)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        # Help
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "CrawlLens - Web Scraper\nVersion 1.0"))
        menubar.add_cascade(label="Help", menu=help_menu)
        self.root.config(menu=menubar)

    def _setup_dataset_tab(self, parent):
        parent.columnconfigure(0, weight=1)
        # Counters
        counters = ttk.Frame(parent)
        counters.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0,10))
        for i in range(0, 4):
            counters.columnconfigure(i, weight=1)
        self.dataset_pages_var = tk.StringVar(value='0')
        self.dataset_blocks_var = tk.StringVar(value='0')
        self.dataset_tables_var = tk.StringVar(value='0')
        self.dataset_last_export_var = tk.StringVar(value='—')
        ttk.Label(counters, text="Pages:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(counters, textvariable=self.dataset_pages_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(counters, text="Blocks:").grid(row=0, column=2, sticky=tk.W)
        ttk.Label(counters, textvariable=self.dataset_blocks_var).grid(row=0, column=3, sticky=tk.W)
        ttk.Label(counters, text="Tables:").grid(row=1, column=0, sticky=tk.W, pady=(6,0))
        ttk.Label(counters, textvariable=self.dataset_tables_var).grid(row=1, column=1, sticky=tk.W, pady=(6,0))
        ttk.Label(counters, text="Last export path:").grid(row=1, column=2, sticky=tk.W, pady=(6,0))
        ttk.Label(counters, textvariable=self.dataset_last_export_var).grid(row=1, column=3, sticky=tk.W, pady=(6,0))

        # Toggles
        toggles = ttk.LabelFrame(parent, text="Options", padding="10")
        toggles.grid(row=1, column=0, sticky=(tk.W, tk.E))
        ttk.Checkbutton(toggles, text="Use sitemaps for discovery", variable=self.use_sitemaps_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(toggles, text="Export JSONL on finish", variable=self.export_jsonl_on_finish_var).grid(row=0, column=1, sticky=tk.W, padx=(10,0))
        ttk.Checkbutton(toggles, text="Same site only (eTLD+1)", variable=self.same_site_only_var).grid(row=0, column=2, sticky=tk.W, padx=(10,0))
        ttk.Checkbutton(toggles, text="Write Blocks JSONL", variable=self.export_blocks_var).grid(row=0, column=3, sticky=tk.W, padx=(10,0))
        ttk.Checkbutton(toggles, text="Compact Blocks (training-ready)", variable=self.compact_blocks_var).grid(row=0, column=4, sticky=tk.W, padx=(10,0))

        # Depth estimate tools
        est_frame = ttk.LabelFrame(parent, text="Depth estimate (dry run)", padding="10")
        est_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10,0))
        est_frame.columnconfigure(0, weight=1)
        btns = ttk.Frame(est_frame)
        btns.grid(row=0, column=0, sticky=tk.W, pady=(0,6))
        self.depth_estimate_button = ttk.Button(btns, text="Estimate Depth", command=self.run_depth_estimate)
        self.depth_estimate_button.pack(side=tk.LEFT)
        self.stop_estimate_button = ttk.Button(btns, text="Stop", command=self.stop_depth_estimate, state='disabled')
        self.stop_estimate_button.pack(side=tk.LEFT, padx=(6,0))
        self.clear_estimate_button = ttk.Button(btns, text="Clear", command=self.clear_depth_estimate)
        self.clear_estimate_button.pack(side=tk.LEFT, padx=(6,0))
        ttk.Label(btns, text="Max depth: 5, polite & robots-aware; no export").pack(side=tk.LEFT, padx=(10,0))
        # Results area
        self.depth_estimate_text = scrolledtext.ScrolledText(est_frame, height=8, wrap=tk.WORD, font=('Consolas', 9))
        self.depth_estimate_text.grid(row=1, column=0, sticky=(tk.W, tk.E))
        self.depth_estimate_text.config(state=tk.DISABLED)
        # Recommended depth label
        rec = ttk.Frame(est_frame)
        rec.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(6,0))
        ttk.Label(rec, text="Recommended crawl depth:").pack(side=tk.LEFT)
        self.recommended_depth_var = tk.StringVar(value='—')
        ttk.Label(rec, textvariable=self.recommended_depth_var, font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=(6,0))

    def _refresh_dataset_tab(self):
        try:
            self.dataset_pages_var.set(str(self.dataset_pages_count))
            self.dataset_blocks_var.set(str(self.dataset_blocks_count))
            self.dataset_tables_var.set(str(self.dataset_tables_count))
            self.dataset_last_export_var.set(self.last_export_path or '—')
        except Exception:
            pass

    def clear_depth_estimate(self):
        try:
            self.estimate_stop_event.clear()
            self._dataset_clear_text()
            self.recommended_depth_var.set('—')
            self.depth_estimate_button.config(state='normal')
            self.stop_estimate_button.config(state='disabled')
        except Exception:
            pass

    # -------- Depth estimate (dry run) --------
    def run_depth_estimate(self):
        try:
            seed = self.url_entry.get().strip()
            if not seed or not seed.startswith(('http://','https://')):
                messagebox.showerror("Estimate Depth", "Enter a valid seed URL (http/https) in the main URL field.")
                return
            # ensure not cancelled from a previous run
            try:
                self.stop_event.clear()
            except Exception:
                pass
            try:
                self.estimate_stop_event.clear()
            except Exception:
                pass
            self.depth_estimate_button.config(state='disabled')
            self.stop_estimate_button.config(state='normal')
            self.recommended_depth_var.set('—')
            self._dataset_clear_text()
            # immediate feedback
            self._dataset_append_text(f"Starting depth estimate for: {seed}\n")
            threading.Thread(target=self._estimate_depth_worker, args=(seed,), daemon=True).start()
        except Exception:
            try:
                self.depth_estimate_button.config(state='normal')
                self.stop_estimate_button.config(state='disabled')
            except Exception:
                pass

    def _dataset_clear_text(self):
        try:
            self.depth_estimate_text.config(state=tk.NORMAL)
            self.depth_estimate_text.delete(1.0, tk.END)
            self.depth_estimate_text.config(state=tk.DISABLED)
        except Exception:
            pass

    def _dataset_append_text(self, text):
        try:
            self.depth_estimate_text.config(state=tk.NORMAL)
            self.depth_estimate_text.insert(tk.END, text)
            self.depth_estimate_text.see(tk.END)
            self.depth_estimate_text.config(state=tk.DISABLED)
        except Exception:
            pass

    def _estimate_depth_worker(self, seed_url):
        try:
            # Robots and base delay
            is_allowed, robots_delay, _, sitemaps = self.check_robots_txt(seed_url)
            if not is_allowed:
                self.root.after(0, lambda: self._dataset_append_text("Disallowed by robots.txt for seed URL.\n"))
                return
            base_delay = max(float(self.delay_var.get() or 0.0), float(robots_delay or 0.0))

            max_depth = 5
            same_domain_only = bool(self.same_domain_var.get())
            same_site_only = bool(self.same_site_only_var.get())
            use_sitemaps = bool(self.use_sitemaps_var.get())
            base_netloc = urlparse(seed_url).netloc
            base_site = self._etld_plus_one(base_netloc)

            seen = set()
            dq = deque()
            seed_norm = self._normalize_url(seed_url)
            dq.append((seed_norm, 0))
            depth_new = {}
            processed = 0
            max_urls = 1000

            # Optional sitemap seeding at depth 1
            if use_sitemaps and sitemaps and max_depth > 0:
                try:
                    sitemap_urls = self._discover_from_sitemaps(sitemaps, limit=500)
                    self.root.after(0, lambda: self._dataset_append_text(f"Sitemaps discovered: {len(sitemaps)}; URLs from sitemaps: {len(sitemap_urls)}\n"))
                    for su in sitemap_urls:
                        nsu = self._normalize_url(su)
                        if nsu in seen:
                            continue
                        if same_site_only and self._etld_plus_one(urlparse(nsu).netloc) != base_site:
                            continue
                        if same_domain_only and urlparse(nsu).netloc != base_netloc:
                            continue
                        dq.append((nsu, 1))
                except Exception:
                    self.root.after(0, lambda: self._dataset_append_text("Error parsing sitemap(s); continuing without them.\n"))

            self.root.after(0, lambda: self._dataset_append_text("Running dry-run crawl up to depth 5...\n"))
            while dq and not self.stop_event.is_set() and not self.estimate_stop_event.is_set():
                current_url, depth = dq.popleft()
                if current_url in seen:
                    continue
                seen.add(current_url)
                depth_new.setdefault(depth, 0)
                depth_new[depth] += 1
                processed += 1
                if processed % 25 == 0:
                    self.root.after(0, lambda dn=dict(depth_new): self._dataset_append_text("Progress: " + ", ".join([f"d{d}={dn[d]}" for d in sorted(dn.keys())]) + f" | total={sum(dn.values())}\n"))
                if processed >= max_urls:
                    self.root.after(0, lambda: self._dataset_append_text(f"Reached max URL cap ({max_urls}); stopping early.\n"))
                    break
                if depth >= max_depth:
                    continue
                # Respect robots per URL
                if not self._can_fetch(current_url):
                    continue
                # Fetch and extract links politely
                try:
                    new_links, nofollow = self._get_links_for_crawl(current_url, base_delay)
                except Exception:
                    new_links, nofollow = [], False
                if nofollow:
                    continue
                for link in new_links:
                    if self.stop_event.is_set() or self.estimate_stop_event.is_set():
                        break
                    try:
                        if same_site_only and self._etld_plus_one(urlparse(link).netloc) != base_site:
                            continue
                        if same_domain_only and urlparse(link).netloc != base_netloc:
                            continue
                        if link not in seen:
                            dq.append((link, depth + 1))
                    except Exception:
                        continue

            # compute recommendation (adaptive rule)
            D = max_depth
            new_by_depth = [depth_new.get(d, 0) for d in range(0, D+1)]
            recommended = self._recommend_depth(new_by_depth, D)
            hist_lines = [f"Depth {d}: {depth_new.get(d,0)} new pages" for d in range(0, D+1) if d in depth_new or True]
            out = "\n".join(hist_lines) + "\n\n" + f"Recommended depth: {recommended}\n"
            self.root.after(0, lambda: (self._dataset_append_text(out), self.recommended_depth_var.set(str(recommended))))
        finally:
            try:
                self.root.after(0, lambda: (self.depth_estimate_button.config(state='normal'), self.stop_estimate_button.config(state='disabled')))
            except Exception:
                pass

    def stop_depth_estimate(self):
        try:
            self.estimate_stop_event.set()
            self._dataset_append_text("Stop requested. Finishing current request...\n")
        except Exception:
            pass

    def _get_links_for_crawl(self, url, delay_seconds):
        # Returns (internal_links, nofollow)
        # Rate limit per host
        try:
            host = urlparse(url).netloc
            host_delay = max(float(delay_seconds or 0.0), float(self._robots_cache.get(host, (None, 0))[1] or 0.0))
            self._respect_rate_limit(host, host_delay)
        except Exception:
            pass
        # HEAD gate
        try:
            head = self.session.head(url, allow_redirects=True, timeout=10)
            ctype = head.headers.get('Content-Type','')
            if 'text/html' not in ctype:
                return [], False
        except Exception:
            pass
        # GET
        resp = self.session.get(url, timeout=15)
        resp.raise_for_status()
        ctype2 = resp.headers.get('Content-Type','')
        if 'text/html' not in ctype2:
            return [], False
        if len(resp.content) > 3 * 1024 * 1024:
            return [], False
        soup = BeautifulSoup(resp.content, 'html.parser')
        # meta robots
        meta_robots = ''
        try:
            mr = soup.find('meta', attrs={'name': re.compile(r'^robots$', re.I)})
            if mr:
                meta_robots = (mr.get('content') or '').lower()
        except Exception:
            meta_robots = ''
        nofollow = ('nofollow' in meta_robots)
        internal, _ = self._extract_links(soup, url)
        return [self._normalize_url(l) for l in internal], nofollow

    def _recommend_depth(self, new_by_depth, max_depth,
                          large_threshold=200, min_pages=10, min_share=0.05,
                          target_coverage=0.90, drop_ratio=0.30, min_gain=2):
        try:
            total = sum(new_by_depth)
            D = min(len(new_by_depth)-1, max_depth)
            # 1) Large-site rule: keep current behavior
            if total >= large_threshold:
                for d in range(D, -1, -1):
                    if new_by_depth[d] >= min_pages and (new_by_depth[d] / (total or 1)) >= min_share:
                        return d
                # fall through to small-site logic
            # 2) Small-site adaptive
            # coverage depth
            cum = 0
            coverage_depth = None
            for d in range(0, D+1):
                cum += new_by_depth[d]
                if (cum / (total or 1)) >= target_coverage:
                    coverage_depth = d
                    break
            # elbow depth
            elbow_depth = None
            for d in range(1, D+1):
                prev = new_by_depth[d-1]
                threshold = max(min_gain, int(prev * drop_ratio))
                if new_by_depth[d] < threshold:
                    elbow_depth = d - 1
                    break
            # biggest gain (prefer shallower on ties)
            best_gain_depth = 0
            best_tuple = (-1, 0)  # (gain, -depth)
            for i in range(0, D+1):
                tup = (new_by_depth[i], -i)
                if tup > best_tuple:
                    best_tuple = tup
                    best_gain_depth = i
            candidates = [best_gain_depth]
            if coverage_depth is not None:
                candidates.append(coverage_depth)
            if elbow_depth is not None:
                candidates.append(elbow_depth)
            return min(min(candidates), D)
        except Exception:
            return 0

    def _toggle_advanced(self):
        try:
            if self.advanced_frame.winfo_ismapped():
                self.advanced_frame.grid_remove()
            else:
                self.advanced_frame.grid()
        except Exception:
            pass

    def _set_theme(self, name: str):
        try:
            tb.Style().theme_use(name)
        except Exception:
            try:
                messagebox.showerror("Theme", f"Unable to apply theme: {name}")
            except Exception:
                pass

    def _sort_history_by(self, col, descending):
        try:
            data = [(self.history_tree.set(child, col), child) for child in self.history_tree.get_children('')]
            if col in ("Content Length", "Images", "Links"):
                data.sort(key=lambda t: int(t[0].replace(',', '')), reverse=descending)
            else:
                data.sort(reverse=descending)
            for index, (val, child) in enumerate(data):
                self.history_tree.move(child, '', index)
            self.history_tree.heading(col, command=lambda c=col: self._sort_history_by(c, not descending))
        except Exception:
            pass

    def export_history(self):
        try:
            filetypes = (("JSON", "*.json"), ("CSV", "*.csv"))
            path = filedialog.asksaveasfilename(title="Export History", defaultextension=".json", filetypes=filetypes)
            if not path:
                return
            if path.lower().endswith('.csv'):
                with open(path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(["timestamp", "url", "title", "heading", "content_length", "images_count", "links_count"])
                    for e in self.history.get_history():
                        writer.writerow([e.get('timestamp',''), e.get('url',''), e.get('title',''), e.get('heading',''), e.get('content_length',0), e.get('images_count',0), e.get('links_count',0)])
            else:
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self.history.get_history(), f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Export", f"History exported to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def export_results(self):
        try:
            content = self.results_text.get(1.0, tk.END)
            if not content.strip():
                messagebox.showinfo("Export Results", "No results to export")
                return
            path = filedialog.asksaveasfilename(title="Export Results", defaultextension=".txt", filetypes=(("Text", "*.txt"), ("Markdown", "*.md")))
            if not path:
                return
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            messagebox.showinfo("Export", f"Results exported to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

def main():
    # Use ttkbootstrap window for modern look if available; otherwise fallback to Tk
    if tb:
        root = tb.Window(themename="flatly")
    else:
        root = tk.Tk()
    app = WebScraperGUI(root)
    # Make layout responsive
    try:
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
    except Exception:
        pass
    # Prefer opening maximized so all content is visible without resizing
    try:
        root.state('zoomed')  # Windows
    except Exception:
        try:
            root.attributes('-zoomed', True)  # Some Linux Tk builds
        except Exception:
            try:
                # As a fallback, set a reasonable minimum size
                root.update_idletasks()
                root.minsize(max(1000, root.winfo_width()), max(700, root.winfo_height()))
            except Exception:
                pass
    root.mainloop()

if __name__ == "__main__":
    main()
# CrawlLens — GUI (Tkinter/ttkbootstrap)
# Author: Sachin Chhetri
# Year: 2025
# License: MIT

import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter import font as tkfont
import webbrowser
from datetime import datetime

try:
	import ttkbootstrap as tb
except Exception:
	tb = None

from ..config import Settings
from ..core.crawl import Crawler, CrawlOptions
from ..logging_config import configure_logging
from ..storage.history import ScrapingHistory


class AppGUI:
	"""GUI shell delegating crawling to core Crawler, keeping worker thread and UI queue."""

	def __init__(self, root):
		self.root = root
		self.root.title("CrawlLens - Web Scraper")
		self.root.geometry("1200x1000")
		self.history = ScrapingHistory()
		self.ui_queue = queue.Queue()
		self.stop_event = threading.Event()
		self.settings = Settings()
		configure_logging(level=self.settings.log_level)
		self.crawler = Crawler(user_agent=self.settings.user_agent, data_dir=self.settings.data_dir, retries=self.settings.retries, backoff=self.settings.backoff)
		self._last_sitemaps = []
		self._dataset_pages = 0
		self._dataset_blocks = 0
		self._dataset_tables = 0
		self._last_export_path = ''
		self._build_ui()
		self.root.after(100, self._drain_ui_queue)

	def _build_ui(self):
		# Content container with vertical scrollbar so footer stays visible at any window size
		content = ttk.Frame(self.root)
		content.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
		self.root.columnconfigure(0, weight=1)
		self.root.rowconfigure(0, weight=1)
		content.columnconfigure(0, weight=1)
		content.rowconfigure(0, weight=1)
		canvas = tk.Canvas(content, borderwidth=0, highlightthickness=0)
		vscroll = ttk.Scrollbar(content, orient="vertical", command=canvas.yview)
		canvas.configure(yscrollcommand=vscroll.set)
		canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
		vscroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
		main_frame = ttk.Frame(canvas, padding="20")
		main_window = canvas.create_window((0, 0), window=main_frame, anchor='nw')
		def _on_frame_configure(event):
			canvas.configure(scrollregion=canvas.bbox("all"))
		main_frame.bind('<Configure>', _on_frame_configure)
		def _on_canvas_configure(event):
			canvas.itemconfigure(main_window, width=event.width)
		canvas.bind('<Configure>', _on_canvas_configure)
		main_frame.columnconfigure(1, weight=1)
		main_frame.rowconfigure(4, weight=1)
		title_label = ttk.Label(main_frame, text="CrawlLens", font=tkfont.Font(size=24, weight='bold'))
		title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
		self._build_menu()
		url_frame = ttk.LabelFrame(main_frame, text="Enter URL to Scrape", padding="10")
		url_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 20))
		url_frame.columnconfigure(1, weight=1)
		ttk.Label(url_frame, text="URL:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
		self.url_entry = ttk.Entry(url_frame, width=60, font=('Arial', 10))
		self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
		self.url_entry.bind('<Return>', lambda e: self.start_scraping())
		self.advanced_frame = ttk.LabelFrame(url_frame, text="Advanced options", padding="10")
		self.advanced_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
		self.depth_var = tk.IntVar(value=self.settings.max_depth)
		self.delay_var = tk.DoubleVar(value=self.settings.min_delay)
		self.same_domain_var = tk.BooleanVar(value=self.settings.same_domain_only)
		self.same_site_var = tk.BooleanVar(value=self.settings.same_site_only)
		self.use_sitemaps_var = tk.BooleanVar(value=self.settings.use_sitemaps)
		self.export_jsonl_var = tk.BooleanVar(value=self.settings.export_jsonl)
		self.export_blocks_var = tk.BooleanVar(value=self.settings.export_blocks)
		self.compact_blocks_var = tk.BooleanVar(value=self.settings.compact_blocks)
		ttk.Label(self.advanced_frame, text="Crawl depth:").grid(row=0, column=0, sticky=tk.W)
		self.depth_spin = ttk.Spinbox(self.advanced_frame, from_=0, to=5, textvariable=self.depth_var, width=5)
		self.depth_spin.grid(row=0, column=1, padx=(5, 15))
		ttk.Label(self.advanced_frame, text="Min delay (s):").grid(row=0, column=2, sticky=tk.W)
		self.delay_spin = ttk.Spinbox(self.advanced_frame, from_=0.0, to=10.0, increment=0.5, textvariable=self.delay_var, width=6)
		self.delay_spin.grid(row=0, column=3, padx=(5, 15))
		self.same_domain_chk = ttk.Checkbutton(self.advanced_frame, text="Same domain only", variable=self.same_domain_var)
		self.same_domain_chk.grid(row=0, column=4, padx=(0, 15))
		self.same_site_chk = ttk.Checkbutton(self.advanced_frame, text="Same site only", variable=self.same_site_var)
		self.same_site_chk.grid(row=0, column=5, padx=(0, 10))
		self.use_sitemaps_chk = ttk.Checkbutton(self.advanced_frame, text="Use sitemaps", variable=self.use_sitemaps_var)
		self.use_sitemaps_chk.grid(row=0, column=6, padx=(0, 10))
		self.export_jsonl_chk = ttk.Checkbutton(self.advanced_frame, text="Export JSONL", variable=self.export_jsonl_var)
		self.export_jsonl_chk.grid(row=0, column=7, padx=(0, 10))
		self.export_blocks_chk = ttk.Checkbutton(self.advanced_frame, text="Write blocks", variable=self.export_blocks_var)
		self.export_blocks_chk.grid(row=0, column=8, padx=(0, 10))
		self.compact_blocks_chk = ttk.Checkbutton(self.advanced_frame, text="Compact blocks", variable=self.compact_blocks_var)
		self.compact_blocks_chk.grid(row=0, column=9, padx=(0, 10))
		button_frame = ttk.Frame(main_frame)
		button_frame.grid(row=2, column=0, columnspan=3, pady=(0, 20))
		self.start_button = ttk.Button(button_frame, text="Start", command=self.start_scraping)
		self.start_button.pack(side=tk.LEFT, padx=(0, 10))
		self.cancel_button = ttk.Button(button_frame, text="Cancel", command=self.cancel_scraping)
		self.cancel_button.pack(side=tk.LEFT, padx=(0, 10))
		self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
		self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
		self.export_results_button = ttk.Button(button_frame, text="Export Results", command=self.export_results)
		self.export_results_button.pack(side=tk.LEFT, padx=(0, 10))
		self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
		self.progress.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
		self.notebook = ttk.Notebook(main_frame)
		self.notebook.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
		results_frame = ttk.Frame(self.notebook, padding="10")
		self.notebook.add(results_frame, text="Scraping Results")
		results_frame.columnconfigure(0, weight=1)
		results_frame.rowconfigure(1, weight=1)
		self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, font=('Consolas', 9), height=20)
		self.results_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
		self.results_text.tag_configure('url', foreground='blue', underline=True)
		self.results_text.tag_bind('url', '<Button-1>', self._open_link)
		history_frame = ttk.Frame(self.notebook, padding="10")
		self.notebook.add(history_frame, text="Scraping History")
		history_frame.columnconfigure(0, weight=1)
		history_frame.rowconfigure(1, weight=1)
		self.history_tree = ttk.Treeview(history_frame, columns=("Timestamp", "URL", "Title", "Content Length", "Images", "Links"), show='headings', height=15)
		for c in ("Timestamp", "URL", "Title", "Content Length", "Images", "Links"):
			self.history_tree.heading(c, text=c)
		self.history_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
		self._refresh_history()
		self.status_var = tk.StringVar(value="Ready to scrape")
		status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
		status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))
		# Keep footer visible even at very small window heights
		try:
			self.root.rowconfigure(1, minsize=26)
		except Exception:
			pass

	def _build_menu(self):
		menubar = tk.Menu(self.root)
		file_menu = tk.Menu(menubar, tearoff=0)
		file_menu.add_command(label="Export Results", command=self.export_results)
		file_menu.add_separator()
		file_menu.add_command(label="Quit", command=self.root.quit)
		menubar.add_cascade(label="File", menu=file_menu)
		self.root.config(menu=menubar)

	def start_scraping(self):
		url = self.url_entry.get().strip()
		if not url:
			messagebox.showerror("Error", "Please enter a URL")
			return
		self.start_button.config(state='disabled')
		self.cancel_button.config(state='normal')
		self.progress.start()
		self.status_var.set("Scraping in progress...")
		self.results_text.delete(1.0, tk.END)
		self.stop_event.clear()
		opt = CrawlOptions(
			max_depth=max(0, int(self.depth_var.get() or 0)),
			min_delay=max(0.0, float(self.delay_var.get() or 0.0)),
			same_domain_only=bool(self.same_domain_var.get()),
			same_site_only=bool(self.same_site_var.get()),
			use_sitemaps=bool(self.use_sitemaps_var.get()),
			export_jsonl=bool(self.export_jsonl_var.get()),
			export_blocks=bool(self.export_blocks_var.get()),
			compact_blocks=bool(self.compact_blocks_var.get()),
		)
		threading.Thread(target=self._worker, args=(url, opt), daemon=True).start()

	def cancel_scraping(self):
		self.stop_event.set()
		self.status_var.set("Cancelling...")

	def _worker(self, url, opt: CrawlOptions):
		def stop_flag():
			return self.stop_event.is_set()
		self._log(f"Processing URL: {url}\n\n")
		res = self.crawler.crawl(url, opt, stop_flag=stop_flag)
		self._last_sitemaps = res.sitemaps
		self._dataset_pages += res.pages_count
		self._dataset_blocks += res.blocks_count
		self._dataset_tables += res.tables_count
		self._last_export_path = res.last_export_path
		self.root.after(0, self._finish)

	def _finish(self):
		self.start_button.config(state='normal')
		self.cancel_button.config(state='disabled')
		self.progress.stop()
		self.status_var.set("Scraping completed")
		self.results_text.see(tk.END)
		self._refresh_history()

	def _log(self, text: str):
		try:
			self.ui_queue.put_nowait(text)
		except Exception:
			pass

	def _drain_ui_queue(self):
		try:
			while True:
				text = self.ui_queue.get_nowait()
				self._insert_with_links(text)
		except queue.Empty:
			pass
		self.root.after(100, self._drain_ui_queue)

	def _insert_with_links(self, text: str):
		import re
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

	def _refresh_history(self):
		for item in self.history_tree.get_children():
			self.history_tree.delete(item)
		for entry in reversed(self.history.get_history()):
			timestamp = datetime.fromisoformat(entry['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
			title = entry['title'][:50] + '...' if len(entry['title']) > 50 else entry['title']
			url = entry['url'][:80] + '...' if len(entry['url']) > 80 else entry['url']
			self.history_tree.insert('', 'end', values=(timestamp, url, title, f"{entry['content_length']:,}", entry['images_count'], entry['links_count']))

	def clear_results(self):
		self.results_text.delete(1.0, tk.END)
		self.status_var.set("Results cleared")

	def export_results(self):
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


def main():
	root = tb.Window(themename="flatly") if tb else tk.Tk()
	app = AppGUI(root)
	try:
		root.columnconfigure(0, weight=1)
		root.rowconfigure(0, weight=1)
	except Exception:
		pass
	root.mainloop()


if __name__ == "__main__":
	main()

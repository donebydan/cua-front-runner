from playwright.sync_api import sync_playwright, Browser, BrowserContext, Page
from typing import Optional


class PlaywrightControl:
    """Playwright browser adapter — drop-in replacement for DockerControl.

    Manages a headless (or headed) Chromium browser session via Playwright,
    exposing the same pause/unpause/is_running/is_paused interface that
    the orchestrator expects.
    """

    def __init__(self, headless: bool = True, viewport: tuple[int, int] = (1024, 768)):
        self._headless = headless
        self._viewport = viewport

        self._pw = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None
        self._paused: bool = False

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self, start_url: str = "about:blank") -> "PlaywrightControl":
        """Launch the browser and open the first page."""
        self._pw = sync_playwright().start()
        w, h = self._viewport
        self._browser = self._pw.chromium.launch(
            headless=self._headless,
            args=[f"--window-size={w},{h}", "--disable-extensions"],
        )
        self._context = self._browser.new_context(
            viewport={"width": w, "height": h},
        )
        self._context.on("page", self._on_new_page)
        self._page = self._context.new_page()
        self._page.on("close", self._on_page_close)
        if start_url:
            self._page.goto(start_url)
        self._paused = False
        return self

    def stop(self):
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        self._browser = None
        self._context = None
        self._page = None
        self._pw = None

    def pause(self):
        self._paused = True

    def unpause(self):
        self._paused = False

    def is_running(self) -> bool:
        try:
            return self._browser is not None and self._browser.is_connected()
        except Exception:
            return False

    def is_paused(self) -> bool:
        return self._paused and self.is_running()

    @property
    def page(self) -> Optional[Page]:
        return self._page

    def current_url(self) -> str:
        if self._page:
            return self._page.url
        return ""

    def screenshot_b64(self) -> str:
        import base64
        if not self._page:
            return ""
        png = self._page.screenshot(full_page=False)
        return base64.b64encode(png).decode("utf-8")

    def inject_element(self, html: str) -> None:
        if self._page:
            self._page.evaluate(
                """(html) => {
                    const div = document.createElement('div');
                    div.innerHTML = html;
                    document.body.appendChild(div);
                }""",
                html,
            )

    def goto(self, url: str) -> None:
        if self._page:
            self._page.goto(url)

    def _on_new_page(self, page: Page):
        self._page = page
        page.on("close", self._on_page_close)

    def _on_page_close(self, page: Page):
        if self._page is page:
            pages = self._context.pages if self._context else []
            self._page = pages[-1] if pages else None

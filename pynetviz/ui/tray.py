from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class SystemTray:
    """Cross-platform system tray with connection count stats."""

    def __init__(
        self,
        on_show: Callable[[], None],
        on_quit: Callable[[], None],
        app_name: str = "PyNetViz",
    ) -> None:
        self.on_show = on_show
        self.on_quit = on_quit
        self.app_name = app_name
        self._icon = None
        self._thread: Optional[threading.Thread] = None
        self._connection_count = 0

    def start(self) -> None:
        try:
            import pystray
            from PIL import Image, ImageDraw
        except ImportError:
            logger.warning("pystray/Pillow not available; system tray disabled")
            return

        def create_image() -> "Image.Image":
            # Match app accent (#4FC3F7) on dark shell (#0B0F14)
            img = Image.new("RGB", (64, 64), color=(11, 15, 20))
            draw = ImageDraw.Draw(img)
            draw.ellipse((10, 10, 54, 54), fill=(79, 195, 247))
            draw.ellipse((22, 22, 42, 42), fill=(11, 15, 20))
            draw.rectangle((30, 14, 34, 30), fill=(79, 195, 247))
            return img

        def setup(icon) -> None:
            icon.visible = True

        def show_action(_icon, _item) -> None:
            self.on_show()

        def quit_action(_icon, _item) -> None:
            self.on_quit()
            if self._icon:
                self._icon.stop()

        menu = pystray.Menu(
            pystray.MenuItem("Show PyNetViz", show_action, default=True),
            pystray.MenuItem("Quit", quit_action),
        )

        self._icon = pystray.Icon(
            self.app_name,
            create_image(),
            f"{self.app_name} — 0 connections",
            menu,
        )

        self._thread = threading.Thread(target=self._icon.run, kwargs={"setup": setup}, daemon=True)
        self._thread.start()

    def update_stats(self, connection_count: int, *, unread_alerts: int = 0) -> None:
        self._connection_count = connection_count
        if self._icon:
            alert_bit = f" · {unread_alerts} alert{'s' if unread_alerts != 1 else ''}" if unread_alerts else ""
            self._icon.title = (
                f"{self.app_name} — {connection_count} active connections{alert_bit}"
            )

    def notify_alert(self, title: str, body: str = "") -> None:
        """Best-effort tray balloon; falls back to title text."""
        if not self._icon:
            return
        try:
            # pystray notify is platform-dependent
            if hasattr(self._icon, "notify"):
                self._icon.notify(body or title, title)
            else:
                self._icon.title = f"{self.app_name}: {title}"
        except Exception:
            logger.debug("tray notify failed", exc_info=True)

    def stop(self) -> None:
        if self._icon:
            try:
                self._icon.stop()
            except Exception:
                pass
from __future__ import annotations

import platform
import sys


def get_platform_label() -> str:
    return f"{platform.system()} {platform.release()}"


def needs_elevation_hint() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes

            return not ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return True
    return False
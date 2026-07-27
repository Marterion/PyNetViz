"""Navigation and selection state."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


TAB_DASHBOARD = 0
TAB_PROCESSES = 1
TAB_SECURITY = 2
TAB_INSIGHTS = 3
TAB_HISTORY = 4
TAB_SETTINGS = 5
TAB_COUNT = 6
TAB_NAMES = (
    "Dashboard",
    "Processes",
    "Security",
    "Insights",
    "History",
    "Settings",
)

TAB_ICONS = (
    "DASHBOARD_OUTLINED",
    "APPS_OUTLINED",
    "SECURITY_OUTLINED",
    "INSIGHTS_OUTLINED",
    "HISTORY_OUTLINED",
    "SETTINGS_OUTLINED",
)


@dataclass
class ProcessSelection:
    pid: Optional[int] = None
    name: Optional[str] = None

    @property
    def is_selected(self) -> bool:
        return self.pid is not None

    def clear(self) -> None:
        self.pid = None
        self.name = None

    def select(self, pid: int, name: str) -> None:
        self.pid = int(pid)
        self.name = str(name)


@dataclass
class NavigationState:
    tab_index: int = TAB_DASHBOARD
    process: ProcessSelection = field(default_factory=ProcessSelection)
    sidebar_collapsed: bool = False
    live_paused: bool = False

    def switch_tab(self, index: int) -> bool:
        if not isinstance(index, int):
            raise TypeError("tab index must be int")
        if index < 0 or index >= TAB_COUNT:
            raise ValueError(f"tab index out of range: {index}")
        if index == self.tab_index:
            return False
        self.tab_index = index
        return True

    def select_process(self, pid: int, name: str) -> None:
        self.process.select(pid, name)

    def clear_process(self) -> None:
        self.process.clear()

    def toggle_sidebar(self) -> bool:
        self.sidebar_collapsed = not self.sidebar_collapsed
        return self.sidebar_collapsed

    def toggle_pause(self) -> bool:
        self.live_paused = not self.live_paused
        return self.live_paused

    def set_paused(self, paused: bool) -> None:
        self.live_paused = bool(paused)

    @property
    def tab_name(self) -> str:
        return TAB_NAMES[self.tab_index]

    def is_dashboard(self) -> bool:
        return self.tab_index == TAB_DASHBOARD

    def is_processes(self) -> bool:
        return self.tab_index == TAB_PROCESSES

    def is_security(self) -> bool:
        return self.tab_index == TAB_SECURITY

    def is_insights(self) -> bool:
        return self.tab_index == TAB_INSIGHTS

    def is_history(self) -> bool:
        return self.tab_index == TAB_HISTORY

    def is_settings(self) -> bool:
        return self.tab_index == TAB_SETTINGS

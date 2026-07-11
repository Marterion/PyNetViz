"""Pure navigation / selection state — no Flet dependency.

Unit-tested independently of the GUI so tab switches and process selection
stay correct even when the UI layer is busy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


TAB_DASHBOARD = 0
TAB_CONNECTIONS = 1
TAB_PROCESSES = 2
TAB_COUNT = 3
TAB_NAMES = ("Dashboard", "Connections", "Processes")


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
    """Single source of truth for which tab is active and process selection."""

    tab_index: int = TAB_DASHBOARD
    process: ProcessSelection = field(default_factory=ProcessSelection)
    connection_process_filter: str = ""

    def switch_tab(self, index: int) -> bool:
        """Switch tab. Returns True if the index changed."""
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
        self.connection_process_filter = name

    def clear_process(self) -> None:
        self.process.clear()
        self.connection_process_filter = ""

    @property
    def tab_name(self) -> str:
        return TAB_NAMES[self.tab_index]

    def is_dashboard(self) -> bool:
        return self.tab_index == TAB_DASHBOARD

    def is_connections(self) -> bool:
        return self.tab_index == TAB_CONNECTIONS

    def is_processes(self) -> bool:
        return self.tab_index == TAB_PROCESSES

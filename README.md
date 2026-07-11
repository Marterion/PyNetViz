# PyNetViz

Real-time **Network Connections Visualizer and Analyzer** for Windows, Linux, and macOS.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Features

- **Live dashboard** — connection counts, listening/established stats, top processes, bandwidth charts
- **Connections table** — sortable, searchable, filterable with color-coded states and detail pane
- **Per-process view** — group connections by process with activity charts
- **Real-time polling** — background updates via `psutil`
- **DNS resolution** — reverse DNS with LRU cache
- **WHOIS & GeoIP** — right-click lookups (API fallback + optional MaxMind GeoLite2)
- **System tray** — quick stats and show/hide
- **Dark mode** — modern monitoring UI

## Requirements

- Python 3.11+
- Administrator/root privileges recommended for full connection visibility

## Installation

```bash
cd NetworkAnalyzer
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### Optional: MaxMind GeoLite2

Place `GeoLite2-City.mmdb` in `~/.pynetviz/` or `data/GeoLite2-City.mmdb` for offline GeoIP.

## Usage

```bash
python main.py
```

Or after install:

```bash
pynetviz
```

### Windows (elevated)

For complete connection data, run PowerShell as Administrator:

```powershell
python main.py
```

## Project Structure

```
NetworkAnalyzer/
├── main.py                 # Entry point
├── requirements.txt
├── pyproject.toml
├── tests/                  # Unit tests
└── pynetviz/
    ├── collector/          # psutil polling & bandwidth tracking
    ├── models/             # Data models
    ├── services/           # DNS, GeoIP, WHOIS
    ├── ui/                 # Flet GUI components
    └── utils/              # Platform helpers
```

## Color Legend

| Color  | Meaning                           |
|--------|-----------------------------------|
| Green  | Established outbound              |
| Blue   | Listening                         |
| Orange | Inbound                           |
| Red    | Suspicious port / unknown process |

## Notes

- Per-connection byte counts are estimated from process I/O polling where accessible
- Some system connections require elevated privileges to attribute to processes
- Monitoring only — no firewall or blocking

## License

MIT

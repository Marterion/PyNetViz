# PyNetViz

**Real-time network connections visualizer and analyzer** for Windows, Linux, and macOS.

Desktop app that shows live sockets, groups them by process, scores risk, and runs optional security monitors — monitoring only, not a firewall.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Version](https://img.shields.io/badge/Version-2.0.0-blue)

## Features

| Area | What you get |
|------|----------------|
| **Dashboard** | Ops-style mission bar, connection KPIs, protocol/direction/risk panels, process roster, sparklines |
| **Processes** | Connections grouped by process with activity history and detail selection |
| **Security** | Monitors: suspicious hosts, new devices, evil twin, system files, device list, idle summary, ARP spoof, proxy, traffic, time machine, first activity |
| **Insights** | Network digest, risk highlights, first-seen tracking, alert list |
| **History** | Hourly aggregates and stored connection samples (SQLite) |
| **Settings** | Privacy mode, alert threshold, poll interval, UI density, port labels, monitor toggles |
| **Export** | Live snapshot to CSV/JSON under `~/.pynetviz/exports/` |
| **Tray** | Connection count and unread alert hint |
| **Risk engine** | LOLBins, paths, new remotes, inbound, suspicious ports |

### Tabs

1. Dashboard · 2. Processes · 3. Security · 4. Insights · 5. History · 6. Settings

### Keyboard shortcuts

| Key | Action |
|-----|--------|
| `1`–`6` | Switch tabs |
| `P` | Pause / resume live UI paints (analysis keeps running) |
| `B` | Collapse / expand sidebar |
| `Ctrl+E` | Export live connection snapshot (CSV) |

## Requirements

- **Python 3.11+**
- Administrator / root recommended so process attribution and full socket lists are visible
- Optional: [MaxMind GeoLite2 City](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) database for offline GeoIP

## Installation

```bash
git clone https://github.com/Marterion/PyNetViz.git
cd PyNetViz

python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### Optional offline GeoIP

Place `GeoLite2-City.mmdb` in either:

- `~/.pynetviz/GeoLite2-City.mmdb`, or  
- `data/GeoLite2-City.mmdb` (local `data/` is gitignored)

## Usage

```bash
python main.py
```

After `pip install -e .` (or package install):

```bash
pynetviz
```

### Windows

Double-click or run:

```bat
run_pynetviz.bat
```

For complete connection data, start from an **elevated** PowerShell or Command Prompt:

```powershell
python main.py
```

## Privacy and data

Local data is stored under **`~/.pynetviz/`** (not in this repository):

| Path | Purpose |
|------|---------|
| `analysis.db` | First-seen map, hourly stats, samples, alerts |
| `settings.json` | App preferences |
| `exports/` | Manual CSV/JSON snapshots |
| `GeoLite2-City.mmdb` | Optional offline GeoIP |

### Privacy modes

| Mode | Behavior |
|------|----------|
| **Enrich** (default) | May call public GeoIP / WHOIS APIs for remote IPs |
| **Strict** | Blocks remote enrichment; local MaxMind DB still used if present |

Reverse DNS uses the system resolver. Security monitors may read local OS state (ARP table, hosts file, proxy settings) **on your machine only**.

This app does **not** send your source code, credentials, or repository contents anywhere. Enrichment APIs only receive IP addresses you look up while enrichment is enabled.

## Limitations

- Per-connection byte rates are **estimated** from process I/O when accessible
- Some system sockets need elevation to attribute to a process
- **Monitoring only** — no firewall rules, blocking, or packet capture
- GeoIP fallback uses a public HTTP API when no MaxMind DB is available and enrichment is on

## Project structure

```
PyNetViz/
├── main.py                 # Entry point
├── requirements.txt
├── pyproject.toml
├── run_pynetviz.bat        # Windows launcher (venv + deps)
└── pynetviz/
    ├── analysis/           # Risk, digest, SQLite store, pipeline, settings
    ├── collector/          # psutil polling and bandwidth tracking
    ├── models/             # Connection / process / stats models
    ├── security/           # Detectors and security engine
    ├── services/           # DNS, GeoIP, WHOIS
    ├── ui/                 # App shell, dashboard, views, theme, tray
    └── utils/              # Formatters, port labels, export, platform helpers
```

## Color legend

| Color | Meaning |
|-------|---------|
| Green | Established outbound / low risk |
| Blue | Listening |
| Orange | Inbound / elevated risk |
| Red | High risk / suspicious |
| Cyan | Accent / selection |

## Dependencies

- [Flet](https://flet.dev/) — UI  
- [psutil](https://github.com/giampaolo/psutil) — process and socket inventory  
- [requests](https://requests.readthedocs.io/) — optional enrichment HTTP  
- [geoip2](https://github.com/maxmind/GeoIP2-python) — optional MaxMind reader  
- [Pillow](https://python-pillow.org/) + [pystray](https://github.com/moses-palmer/pystray) — system tray  

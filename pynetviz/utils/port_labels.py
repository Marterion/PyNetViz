"""Well-known TCP/UDP port labels for UI enrichment."""

from __future__ import annotations

from typing import Optional

from pynetviz.utils.netaddrs import is_unspecified_addr

# Curated common services — not exhaustive, UI-friendly labels.
WELL_KNOWN_PORTS: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    514: "Syslog",
    587: "Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle",
    1723: "PPTP",
    1883: "MQTT",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2181: "ZooKeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Dev-HTTP",
    3306: "MySQL",
    3389: "RDP",
    3478: "STUN",
    4000: "Alt-HTTP",
    4443: "HTTPS-Alt",
    5000: "UPnP/Dev",
    5222: "XMPP",
    5269: "XMPP-S2S",
    5353: "mDNS",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    5938: "TeamViewer",
    6379: "Redis",
    6443: "K8s-API",
    6667: "IRC",
    6881: "BitTorrent",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    9000: "Dev/Portainer",
    9001: "Tor-OR",
    9050: "Tor-SOCKS",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "ES-Transport",
    9418: "Git",
    11211: "Memcached",
    27017: "MongoDB",
    32400: "Plex",
    51820: "WireGuard",
}


def port_label(port: int) -> Optional[str]:
    """Return service label for a port, or None if unknown."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return None
    return WELL_KNOWN_PORTS.get(p)


def format_port(port: int, *, with_label: bool = True) -> str:
    """`443 (HTTPS)` or just `443`."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return str(port)
    if not with_label:
        return str(p)
    label = port_label(p)
    if label:
        return f"{p} ({label})"
    return str(p)


def format_endpoint(addr: str, port: int, *, with_label: bool = True) -> str:
    """`8.8.8.8:443 (HTTPS)` style endpoint."""
    if is_unspecified_addr(addr):
        return f"*:{format_port(port, with_label=with_label)}" if port else "*:*"
    return f"{addr}:{format_port(port, with_label=with_label)}"

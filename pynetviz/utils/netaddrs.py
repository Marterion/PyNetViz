"""Address classification used across collector, risk, and enrichment."""

from __future__ import annotations

import ipaddress

UNSPECIFIED_ADDRS = frozenset({"", "0.0.0.0", "::", "*"})
LOOPBACK_ADDRS = frozenset({"127.0.0.1", "::1"})


def is_unspecified_addr(addr: str | None) -> bool:
    """True for empty / wildcard listen endpoints."""
    return (not addr) or addr in UNSPECIFIED_ADDRS


def is_non_public_ip(addr: str | None) -> bool:
    """True for unspecified, loopback, private, link-local, multicast, or unparseable."""
    if is_unspecified_addr(addr) or addr in LOOPBACK_ADDRS:
        return True
    try:
        ip = ipaddress.ip_address(str(addr).split("%", 1)[0])
    except ValueError:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
    )

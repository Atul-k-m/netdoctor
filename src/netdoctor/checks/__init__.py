"""The checks, in the order they run: bottom-up, each layer depending on the one below."""

from . import dns, http, icmp, local, path, pmtu, tcp, tls

CHECKS = [local, dns, icmp, path, tcp, pmtu, tls, http]
CHECK_IDS = [m.ID for m in CHECKS]

__all__ = ["CHECKS", "CHECK_IDS"]

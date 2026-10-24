"""Explicit, fail-closed selection of one public V3 anisette endpoint.

A public service operator can observe an IP, pseudonymous client identifier,
and opaque provisioning blobs. No public server can be certified safe by us.
"""
from __future__ import annotations

from urllib.parse import urlparse

# Community-run HTTPS endpoints from SideStore's maintained V3 list.
# The app NEVER discovers fallback hosts over the network.
SERVERS = {
    "SideStore V3": "https://new.ani.sidestore.io",
    "jkcoxson Mac V3": "https://mac-ani.jkcoxson.com",
}
APPLE_HOSTS = frozenset({
    "gsa.apple.com",
    "developerservices2.apple.com",
})


def selected_url(label: str) -> str:
    if label not in SERVERS:
        raise ValueError("Select one of the preapproved Anisette V3 servers")
    return SERVERS[label]


def server_host(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or url not in SERVERS.values():
        raise ValueError("Unrecognized or non-HTTPS Anisette server")
    assert parsed.hostname is not None
    return parsed.hostname.lower()


def allowed_host(host: str, server_url: str) -> bool:
    return str(host).lower().rstrip(".") in APPLE_HOSTS | {server_host(server_url)}

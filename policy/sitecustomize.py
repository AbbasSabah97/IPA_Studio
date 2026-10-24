"""Network egress guard loaded automatically by the bundled engine interpreter.

Deny remote DNS and sockets except the explicit Apple endpoints and ONE approved
V3 Anisette hostname, chosen in the GUI. USB access to local usbmux remains.

Python-level defense-in-depth, NOT an OS firewall or malware sandbox. Native code,
OS services, and alternative socket APIs are outside this guard's full scope.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import threading
from urllib.parse import urlparse

APPLE_HOSTS = frozenset(("gsa.apple.com", "developerservices2.apple.com"))
PUBLIC_V3 = frozenset(("new.ani.sidestore.io", "mac-ani.jkcoxson.com"))
_SERVER = os.environ.get("IPASTUDIO_APPROVED_ANISETTE", "")
_HOST = urlparse(_SERVER).hostname or ""
if urlparse(_SERVER).scheme != "https" or _HOST not in PUBLIC_V3:
    _HOST = ""  # No approval: only local USB and predeclared Apple endpoints.

_APPROVED = APPLE_HOSTS | ({_HOST} if _HOST else set())
_lock = threading.RLock()
_approved_ips: set[str] = set()
_orig_getaddrinfo = socket.getaddrinfo
_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex
_orig_sendto = socket.socket.sendto


def _is_loopback(host: object) -> bool:
    try:
        return ipaddress.ip_address(str(host).split("%", 1)[0]).is_loopback
    except ValueError:
        return str(host).lower() == "localhost"


def _clean_ip(host: object) -> str:
    try:
        return str(ipaddress.ip_address(str(host).split("%", 1)[0]))
    except ValueError:
        return ""


def _permitted_address(host: object) -> bool:
    if _is_loopback(host):
        return True
    ip = _clean_ip(host)
    with _lock:
        return bool(ip and ip in _approved_ips)


def guarded_getaddrinfo(host, *args, **kwargs):
    # Bare DNS IPs are checked against addresses already resolved for allowed hosts.
    if host is not None and not _is_loopback(host):
        key = host.decode("ascii", "strict") if isinstance(host, bytes) else str(host)
        if key.lower().rstrip(".") not in _APPROVED:
            if not _permitted_address(key):
                raise PermissionError("IPA Studio network policy blocked DNS: " + key[:150])
        else:
            results = _orig_getaddrinfo(host, *args, **kwargs)
            with _lock:
                for result in results:
                    if result[4] and result[4][0]:
                        _approved_ips.add(_clean_ip(result[4][0]))
            return results
    return _orig_getaddrinfo(host, *args, **kwargs)


def _check_address(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        host = address[0] if isinstance(address, tuple) and address else ""
        if not _permitted_address(host):
            raise PermissionError("IPA Studio network policy blocked outbound connection")
        if not _is_loopback(host):
            port = address[1] if len(address) > 1 else None
            if port != 443:
                raise PermissionError("IPA Studio network policy permits remote HTTPS port 443 only")


def guarded_connect(sock, address):
    _check_address(sock, address)
    return _orig_connect(sock, address)


def guarded_connect_ex(sock, address):
    _check_address(sock, address)
    return _orig_connect_ex(sock, address)


def guarded_sendto(sock, data, *args, **kwargs):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        addr = kwargs.get("address") or (args[-1] if args else None)
        _check_address(sock, addr)
    return _orig_sendto(sock, data, *args, **kwargs)


socket.getaddrinfo = guarded_getaddrinfo
socket.socket.connect = guarded_connect
socket.socket.connect_ex = guarded_connect_ex
socket.socket.sendto = guarded_sendto
# Explicitly deny proxy redirection of sensitive Apple authentication requests.
for _name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
    os.environ.pop(_name, None)
os.environ["NO_PROXY"] = "*"
os.environ["IPASTUDIO_EGRESS_GUARD"] = "enabled"

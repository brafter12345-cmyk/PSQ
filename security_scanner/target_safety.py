"""Connection-time public-address enforcement for scanner target probes."""
import ipaddress
import socket


class UnsafeTarget(OSError):
    """A target has no exclusively public address set."""


def public_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        if getattr(ip, "ipv4_mapped", None) is not None:
            ip = ip.ipv4_mapped
        return bool(ip.is_global and not (ip.is_multicast or ip.is_reserved
                    or ip.is_unspecified or ip.is_loopback or ip.is_link_local))
    except ValueError:
        return False


def resolve_public(host, port):
    """Resolve once; reject the entire set if even one answer is unsafe."""
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers or any(not public_ip(entry[4][0]) for entry in answers):
        raise UnsafeTarget("target has non-public or empty address set")
    return answers


def connect_public(host, port, timeout=None, source_address=None, socket_options=None):
    """Connect to the resolved sockaddr itself, without a second DNS lookup."""
    answers = resolve_public(host, port)
    last_error = None
    for family, kind, proto, _, address in answers:
        sock = None
        try:
            sock = socket.socket(family, kind, proto)
            if timeout is not None:
                sock.settimeout(timeout)
            for option in socket_options or ():
                sock.setsockopt(*option)
            if source_address:
                sock.bind(source_address)
            sock.connect(address)
            return sock
        except OSError as exc:
            last_error = exc
            if sock is not None:
                sock.close()
    raise last_error or UnsafeTarget("target has no connectable public address")


def safe_request(method, url, **kwargs):
    """Requests session with a pinned transport, including every redirect hop."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.connection import HTTPConnection, HTTPSConnection
    from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

    class PublicConnection:
        def _new_conn(self):
            return connect_public(self.host, self.port, self.timeout,
                                  self.source_address, self.socket_options)

    class PublicHTTPConnection(PublicConnection, HTTPConnection):
        pass

    class PublicHTTPSConnection(PublicConnection, HTTPSConnection):
        pass

    class PublicHTTPPool(HTTPConnectionPool):
        ConnectionCls = PublicHTTPConnection

    class PublicHTTPSPool(HTTPSConnectionPool):
        ConnectionCls = PublicHTTPSConnection

    class PublicAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **options):
            super().init_poolmanager(*args, **options)
            self.poolmanager.pool_classes_by_scheme = {
                "http": PublicHTTPPool, "https": PublicHTTPSPool}

        def proxy_manager_for(self, *args, **kwargs):
            raise UnsafeTarget("proxies are not permitted for target probes")

    if kwargs.get("proxies"):
        raise UnsafeTarget("proxies are not permitted for target probes")
    with requests.Session() as session:
        session.trust_env = False
        session.mount("http://", PublicAdapter())
        session.mount("https://", PublicAdapter())
        return session.request(method, url, **kwargs)

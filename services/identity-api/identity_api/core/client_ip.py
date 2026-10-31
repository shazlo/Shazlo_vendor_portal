import ipaddress

from fastapi import Request

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(cidrs: list[str]) -> list[Network]:
    return [ipaddress.ip_network(cidr) for cidr in cidrs]


def _parse(value: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def client_ip(request: Request, trusted: list[Network]) -> str:
    """The client's IP. `X-Forwarded-For` counts only when the TCP peer is a trusted proxy.

    Each proxy appends the address it saw, so the list is read from the right. The first
    address that is not a trusted proxy is the client; anything further left was written by
    the client and can be anything.
    """
    peer = _parse(request.client.host) if request.client else None
    if peer is None:
        return "unknown"
    if not any(peer in network for network in trusted):
        return str(peer)
    hops = [
        hop for header in request.headers.getlist("x-forwarded-for") for hop in header.split(",")
    ]
    for hop in reversed(hops):
        address = _parse(hop)
        if address is None:
            # A garbled entry: stop here and use the proxy that vouched for it.
            return str(peer)
        if not any(address in network for network in trusted):
            return str(address)
    return str(peer)

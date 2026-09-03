#!/usr/bin/env python3
"""A stateless UDP DNS relay, for the in-box leak-oracle fabric.

===========================================================================
WHY THIS EXISTS AND WHY IT IS THIS SMALL
===========================================================================
The oracle derives a resolver's identity from the SOURCE ADDRESS its query
arrived from (`--resolver <ip>=<id>:<p|u>`), because that is the only thing an
authoritative server can observe about the path a lookup took. So the device's
DNS beacon has to reach the oracle from a resolver's address rather than from
the device's own -- which means something has to sit between them and forward.

`dnsmasq` and `unbound` both cache, both retry, and both health-check. Any one
of those manufactures a DNS arrival during a SILENCE phase, which the oracle
records as a leak and `report.py` turns into a FAIL against the product. That
is the single most dangerous detail in the in-box design, so the relay is
twenty lines with none of those behaviours:

  * NO retries. One datagram in, one datagram out, in each direction. If a
    query is lost it is lost, and the attempt count already carries the
    denominator that makes that visible.
  * NO cache. A cached answer would stop the next beacon from leaving the
    device, and a beacon that never left is not evidence about a kill switch.
  * NO health checks. Nothing here originates a packet on its own; every packet
    it sends is a direct consequence of one it just received.

===========================================================================
THE SOURCE ADDRESS IS THE WHOLE POINT
===========================================================================
`--listen` is where the device sends its queries. `--source` is the address the
relay presents to the oracle, and it is bound explicitly rather than left to
the routing table: on a single host the kernel would otherwise pick the
destination's own interface address, the oracle would see a query that appears
to have arrived from itself, no `--resolver` entry would match, and every DNS
observation would be filed as `dns_resolver_identity_ambiguous` --
INCONCLUSIVE, for a reason nobody would trace back to a source-address choice.

Usage (one process per family):

    dns-forward.py --listen 10.78.0.53:53 --upstream 10.78.0.1:53 \\
                   --source 10.78.0.53
    dns-forward.py --listen '[fd78:7717:d0c::53]:53' \\
                   --upstream '[fd78:7717:d0c::1]:53' --source fd78:7717:d0c::53

`--self-check` forwards exactly one query against a throwaway upstream on
loopback and asserts that one query in produced one query out.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading


def split_hostport(text: str) -> tuple[str, int]:
    """`10.78.0.53:53` or `[fd78::53]:53` -> (host, port)."""
    if text.startswith("["):
        host, _, port = text[1:].partition("]")
        return host, int(port.lstrip(":"))
    host, _, port = text.rpartition(":")
    if not host:
        raise ValueError(f"{text!r} is not <address>:<port>")
    return host, int(port)


def family_of(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def relay(listen: str, upstream: str, source: str, once: bool = False,
          ready: threading.Event | None = None) -> None:
    """Forward datagrams until killed. One socket pair, no state between queries.

    `ready` is set once the listening socket is bound. The self-check waits on
    it rather than sleeping: a race there would show up as an intermittently
    red gate, which is the least useful kind of failure.
    """
    lhost, lport = split_hostport(listen)
    uhost, uport = split_hostport(upstream)
    down = socket.socket(family_of(lhost), socket.SOCK_DGRAM)
    down.bind((lhost, lport))
    if ready is not None:
        ready.set()
    def forward_one(query: bytes, client: tuple) -> None:
        # A NEW upstream socket per query, bound to the source address the
        # oracle is configured to recognise. Per query rather than once,
        # because a long-lived socket is state, and state is what a relay in a
        # silence proof must not have.
        up = socket.socket(family_of(uhost), socket.SOCK_DGRAM)
        try:
            up.bind((source, 0))
            up.settimeout(3.0)
            up.sendto(query, (uhost, uport))
            try:
                answer, _ = up.recvfrom(4096)
            except (socket.timeout, ConnectionResetError):
                # NOT retried. A lost answer is a lost answer; inventing a
                # second query would put an arrival at the oracle that the
                # device never asked for.
                return
            down.sendto(answer, client)
        finally:
            up.close()

    while True:
        try:
            query, client = down.recvfrom(4096)
        except ConnectionResetError:
            # Windows only: the device closed the port a previous answer went
            # to, and its ICMP port-unreachable surfaces here as WSAECONNRESET
            # on the next receive. Nothing arrived; the socket is still usable.
            continue
        # ONE THREAD PER QUERY, so a query the oracle never answers costs only
        # its own three seconds. Serialised, one unanswered query held every
        # query behind it: the sentinel's two-second cadence alone put the relay
        # permanently behind, and the device's beacons never got through.
        if once:
            forward_one(query, client)
            return
        threading.Thread(target=forward_one, args=(query, client), daemon=True).start()


def self_check() -> int:
    """One query in, one query out, and nothing sent that nobody asked for."""
    # A throwaway "oracle" on loopback that answers once and records what it saw.
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.bind(("127.0.0.1", 0))
    up_port = upstream.getsockname()[1]
    seen: list[tuple[bytes, tuple[str, int]]] = []

    def serve() -> None:
        upstream.settimeout(5.0)
        try:
            data, peer = upstream.recvfrom(4096)
        except socket.timeout:
            return
        seen.append((data, peer))
        upstream.sendto(b"ANSWER:" + data, peer)

    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("127.0.0.1", 0))
    listen_port = listener.getsockname()[1]
    listener.close()

    threading.Thread(target=serve, daemon=True).start()
    ready = threading.Event()
    forwarder = threading.Thread(
        target=relay,
        args=(f"127.0.0.1:{listen_port}", f"127.0.0.1:{up_port}", "127.0.0.1"),
        kwargs={"once": True, "ready": ready},
        daemon=True,
    )
    forwarder.start()
    assert ready.wait(5.0), "the relay never bound its listening socket"

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(5.0)
    client.sendto(b"QUERY", ("127.0.0.1", listen_port))
    answer, _ = client.recvfrom(4096)
    assert answer == b"ANSWER:QUERY", answer
    assert len(seen) == 1, f"one query in must be one query out, not {len(seen)}"
    assert seen[0][0] == b"QUERY", seen[0][0]
    assert seen[0][1][0] == "127.0.0.1", "the relay must present --source upstream"

    # And nothing arrives afterwards: no retry, no keepalive, no health check.
    upstream.settimeout(1.0)
    try:
        stray = upstream.recvfrom(4096)
        raise AssertionError(f"the relay sent an unasked-for datagram: {stray!r}")
    except socket.timeout:
        pass
    client.close()
    upstream.close()
    print("dns-forward self-check passed (1 query in, 1 out, 0 unasked-for)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen", help="<address>:<port> the device sends queries to")
    ap.add_argument("--upstream", help="<address>:<port> of the oracle's DNS listener")
    ap.add_argument("--source", help="the address this relay presents to the oracle")
    ap.add_argument("--self-check", action="store_true")
    args = ap.parse_args()
    if args.self_check:
        return self_check()
    if not (args.listen and args.upstream and args.source):
        ap.error("--listen, --upstream and --source are all required")
    relay(args.listen, args.upstream, args.source)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Deterministic normalization for the location strings that feed vulnerability
fingerprinting (Prompt 13, Finding #1).

WHY THIS EXISTS. `matched_at` -- the third segment of a nuclei fingerprint
(`template_id|matcher|matched_at`, see nuclei_runner.parse_vulnerabilities) is
currently whatever raw string nuclei's own engine reports, with no normalization
applied anywhere in the ingestion path. Two requests that a human would call "the
same endpoint" can therefore produce two different fingerprints purely from
surface formatting -- fracturing one real vulnerability into two Vulnerability
rows on the very next scan:

    https://example.com/login    vs  https://EXAMPLE.com/login
    https://example.com:443/foo  vs  https://example.com/foo
    https://example.com          vs  https://example.com/

This module normalizes ONLY the representational differences above -- it never
touches path segments, query strings, or fragments beyond percent-encoding
case, because those can be semantically load-bearing (a path IS the location;
a query parameter IS often the vulnerable input). Query parameter ORDERING is
deliberately left untouched for the same reason: reordering could make two
requests that hit genuinely different code paths (order-dependent parameter
parsing is real, if rare) collapse into one fingerprint. See the module-level
rule table below for the exact, individually-justified list.

COMPATIBILITY. This function's output replaces the raw `matched_at` value at
the point a fingerprint string is BUILT (see nuclei_runner.py). It does not
retroactively touch any already-persisted Vulnerability.fingerprint -- see
that file's own comment for why a backfill is deliberately out of scope. It is
pure, synchronous, has no DB/network dependency, and is idempotent
(normalize(normalize(x)) == normalize(x)) so it is safe to call more than once
on the same value.

RULE TABLE (input -> normalized output -> reason -> collision risk):

  scheme case            "HTTPS://h/x"   -> "https://h/x"
                          Reason: scheme is case-insensitive per RFC 3986 §3.1.
                          Collision risk: none -- schemes are a closed, tiny set.

  host case               "https://EX.com/x" -> "https://ex.com/x"
                          Reason: DNS names are case-insensitive.
                          Collision risk: none for real hostnames. (An IP
                          address is not affected by this step.)

  default port stripping  "https://h:443/x"  -> "https://h/x"
                           "http://h:80/x"    -> "http://h/x"
                          Reason: the default port for a scheme is equivalent
                          to omitting it.
                          Collision risk: none -- an explicit non-default port
                          is always preserved, so a service actually running
                          on a different port never collapses with :443/:80.

  empty path -> "/"        "https://h" -> "https://h/"
                          Reason: RFC 3986 treats an empty path on an
                          authority-based URI as equivalent to "/"; browsers
                          and HTTP servers do too.
                          Collision risk: none for the empty-path case.
                          Deliberately NOT extended to "/foo" vs "/foo/" (see
                          below) since a server can legitimately treat those
                          as different resources (e.g. a directory listing vs
                          a 404) -- collapsing them risks losing a genuine
                          location distinction. Only the true empty-path case
                          is unambiguous.

  fragment stripping       "https://h/x#frag" -> "https://h/x"
                          Reason: the fragment is never sent to the server
                          (RFC 3986 §3.5); it cannot affect which
                          vulnerability was triggered.
                          Collision risk: none -- two requests differing only
                          by fragment are byte-identical on the wire.

  percent-encoding case    "%2Fx" / "%2fx" -> both -> "%2fx" (lowercase hex)
                          Reason: percent-encoding hex digits are
                          case-insensitive (RFC 3986 §2.1); tools disagree on
                          which case they emit for the identical byte.
                          Collision risk: none -- this changes only the ASCII
                          representation of an encoded octet, never its
                          decoded meaning.

  IPv6 host                "https://[::1]:443/x" -> "https://[::1]/x"
                          Reason: same default-port rule, applied to a
                          bracketed IPv6 literal.
                          Collision risk: none.

  host:port (non-HTTP)     "Host.example:8080" -> "host.example:8080"
                          Reason: nmap/naabu-style network findings report
                          bare host:port, not a URL; only host-casing applies
                          (there is no scheme to imply a default port).
                          Collision risk: none.

  query parameter order    LEFT UNTOUCHED
                          Reason: reordering is a semantic assumption this
                          module refuses to make -- see module docstring.
                          Collision risk if normalized: could merge two
                          requests that legitimately differ in server-side
                          parsing order. NOT implemented.

  path trailing slash      LEFT UNTOUCHED beyond the empty-path case above
                          Reason: "/foo" vs "/foo/" can be materially
                          different resources depending on server routing.
                          Collision risk if normalized: could merge two
                          genuinely different endpoints. NOT implemented.

  query value casing/       LEFT UNTOUCHED
  content
                          Reason: query values are often the vulnerable
                          input itself (e.g. an injected payload); casing can
                          be significant to the payload's meaning.
                          Collision risk if normalized: could alter or hide
                          the actual injected value. NOT implemented.
"""
from __future__ import annotations

import re as _re
from urllib.parse import urlsplit, urlunsplit

_DEFAULT_PORTS = {"http": 80, "https": 443}


def _lowercase_percent_escapes(s: str) -> str:
    """Fold the hex digits of every %XX escape to lowercase without touching
    anything else. Deliberately regex-free: a hand-rolled scan is easy to
    reason about as "only characters immediately following a literal '%'
    are ever touched", which is the property idempotency depends on."""
    if "%" not in s:
        return s
    out: list[str] = []
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "%" and i + 2 < n and _is_hex(s[i + 1]) and _is_hex(s[i + 2]):
            out.append("%")
            out.append(s[i + 1].lower())
            out.append(s[i + 2].lower())
            i += 3
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _is_hex(c: str) -> bool:
    return c in "0123456789abcdefABCDEF"


def _normalize_authority(netloc: str, scheme: str) -> str:
    """Lowercase the host, strip a redundant default port, leave userinfo
    (rare on a scan target, but not this function's business to alter) and an
    explicit non-default port untouched."""
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        userinfo += "@"

    # Bracketed IPv6 literal: "[::1]:443" or "[::1]".
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            # Malformed; leave it alone rather than guess.
            return userinfo + hostport
        host = hostport[: end + 1].lower()
        rest = hostport[end + 1 :]
        port = rest[1:] if rest.startswith(":") else (rest or None)
    else:
        if ":" in hostport:
            host, _, port = hostport.rpartition(":")
        else:
            host, port = hostport, None
        host = host.lower()

    default_port = _DEFAULT_PORTS.get(scheme)
    if port and default_port is not None and port.isdigit() and int(port) == default_port:
        port = None

    return userinfo + host + (f":{port}" if port else "")


def normalize_url(value: str) -> str:
    """Normalize a URL for identity purposes. Falls back to returning `value`
    unchanged (never raises) if it doesn't parse as an http(s) URL, so a
    malformed or non-URL matched_at value degrades to today's exact behavior
    rather than corrupting the fingerprint."""
    try:
        parts = urlsplit(value)
    except ValueError:
        return value

    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.netloc:
        # Not an http(s) URL we understand (e.g. already a bare host:port, or
        # something else entirely) -- leave it exactly as-is.
        return value

    netloc = _normalize_authority(parts.netloc, scheme)
    path = _lowercase_percent_escapes(parts.path) or "/"
    query = _lowercase_percent_escapes(parts.query)
    # Fragment is never sent to the server -- drop it (see rule table).
    return urlunsplit((scheme, netloc, path, query, ""))


def normalize_host_port(value: str) -> str:
    """Normalize a bare `host:port` or `host` network location (nmap/naabu-style
    findings, and nuclei's non-HTTP `matched_at` fallback to `host`). Only host
    casing applies -- there is no scheme here to imply a default port."""
    if not value:
        return value
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return value
        return value[: end + 1].lower() + value[end + 1 :]
    host, sep, port = value.partition(":")
    return f"{host.lower()}{sep}{port}"


# ---------------------------------------------------------------------------- SOURCE
# Prompt 35 (Semgrep readiness). A SOURCE-CODE location -- "path/to/File.java:42" or
# "path/to/File.java:42:7" -- is neither a URL nor a host:port, but it contains a colon,
# so `normalize_location` previously fell through to `normalize_host_port`, which
# lowercases everything left of the last colon. That silently corrupted the path:
#
#     src/Auth/LoginHandler.java:42  ->  src/auth/loginhandler.java:42
#
# On any case-sensitive filesystem (every Linux CI checkout) that names a DIFFERENT file.
# As a fingerprint component it is worse than cosmetic: two distinct files differing only
# in case collapse into one identity, and the same file reported with different casing by
# two tools fractures into two. Neither error is visible in the output.
#
# This is a READINESS fix, not a Semgrep integration: no rule engine, no runner, no new
# table. It makes the EXISTING identity path safe for a source location so that a future
# source-code scanner cannot land on a normalizer that corrupts its primary key.
#
# WHAT IS NORMALIZED: separators only (backslash -> forward slash), plus stripping a
# leading "./". Case is PRESERVED, because in a source path case is semantic.
# WHAT IS NOT: the path is never lowercased, never resolved, never made absolute or
# relative to anything -- this module has no filesystem and must stay pure.

# "<path>:<line>" or "<path>:<line>:<col>". The path segment MUST contain a path
# separator ("/" or "\").
#
# A DOT IS DELIBERATELY NOT ENOUGH. An earlier form of this pattern also accepted a dot,
# so that a bare "Main.java:1" would match -- but that made "EXAMPLE.com:8080" and
# "1.2.3.4:80" match too, which would have stopped host-lowercasing for ordinary network
# findings and CHANGED EXISTING fingerprints. Requiring a separator keeps every current
# network location on exactly its current path. The cost is that a source finding reported
# as a bare filename with no directory is still treated as host:port; that is the
# documented readiness boundary, and a repo-relative path (which always has a separator)
# is what a source scanner should emit anyway.
_SOURCE_LOCATION = _re.compile(r"^(?P<path>[^\s:]*[/\\][^\s:]*):(?P<line>\d+)(?::(?P<col>\d+))?$")


def looks_like_source_location(value: str) -> bool:
    """True when `value` is a "file:line[:col]" source reference rather than a network
    location. Deliberately conservative: it requires a path SEPARATOR in the path segment
    AND a numeric line, so "example.com:443" and "1.2.3.4:80" are NOT treated as source. A
    bare hostname with a port is the far more common shape in this pipeline, and
    misclassifying it would change existing network fingerprints."""
    return bool(value) and _SOURCE_LOCATION.match(value) is not None


def normalize_source_location(value: str) -> str:
    """Normalize a "file:line[:col]" source-code location for identity purposes.

    Case-PRESERVING by design (see the block comment above). Returns `value` unchanged if
    it does not match the source shape, so this is safe to call speculatively."""
    m = _SOURCE_LOCATION.match(value or "")
    if m is None:
        return value
    path = m.group("path").replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    line, col = m.group("line"), m.group("col")
    return f"{path}:{line}" + (f":{col}" if col else "")


def normalize_location(value: str | None) -> str | None:
    """Entry point used by fingerprint generation: normalize whatever
    `matched_at` string a tool reported, dispatching on whether it looks like
    a URL, a source-code location, or a bare network location. None/empty input is
    returned unchanged (a fingerprint with no matched_at is already handled upstream)."""
    if not value:
        return value
    if "://" in value:
        return normalize_url(value)
    # Prompt 35: checked BEFORE host:port, because a source location contains a colon and
    # would otherwise be host-lowercased. See the block comment above.
    if looks_like_source_location(value):
        return normalize_source_location(value)
    return normalize_host_port(value)

#!/usr/bin/env python3
"""
php_scan.py - Find web services running PHP across IP address(s) you own, plus
specific URLs / hostnames.

Only scan address space and sites your organization owns or is explicitly
authorized to test. This script does fingerprinting only (ordinary HTTP GET
requests); it does not attempt exploitation.

Detection signals (non-intrusive):
  - X-Powered-By header containing PHP
  - Server header mentioning PHP (e.g. Apache/2.4 PHP/8.1)
  - PHPSESSID cookie
  - Links/forms in the page pointing at .php files
  - The starting URL itself ending in .php
  - /index.php, /phpinfo.php, /info.php responding differently from a
    known-nonexistent path (catch-all/soft-404 servers are filtered out)

Modes (combine freely):
  1. IP sweep:   python3 php_scan.py 203.0.113.0/24
  2. URL list:   python3 php_scan.py --urls urls.txt
  3. Single URL: python3 php_scan.py --url https://app.example.com/login
  4. Both:       python3 php_scan.py 203.0.113.0/24 --urls urls.txt --ptr

URL file format: one entry per line, '#' starts a comment. An entry can be a
full URL (https://app.example.com/portal/) or a bare hostname
(app.example.com), which is tried on every port in --ports.

URLs are requested with the correct Host header and TLS SNI, so name-based
virtual hosts are scanned properly. When a network is given, URLs that
resolve outside of it are skipped unless --allow-outside is set.

Requires only the Python 3 standard library.
"""
#Imports
import argparse
import csv
import http.client
import ipaddress
import random
import re
import socket
import ssl
import string
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

#Variables 
DEFAULT_PORTS = [80, 443, 8080, 8443]
TLS_PORTS = {443, 8443, 4443, 9443}
PROBE_PATHS = ["/index.php", "/phpinfo.php", "/info.php"]
MAX_BODY = 128 * 1024
USER_AGENT = "Mozilla/5.0 (compatible; internal-php-inventory/1.1)"

PHP_HEADER_RE = re.compile(r"php", re.I)
PHP_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["'][^"']*\.php(?:\?[^"']*)?["']""", re.I)

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


#Classes
class _SNIHTTPS(http.client.HTTPSConnection):
    """Connect to a specific IP but present a hostname via SNI."""

    def __init__(self, ip, port, timeout, sni):
        super().__init__(ip, port, timeout=timeout, context=_ctx)
        self._sni = sni

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._sni or self.host)


def port_open(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def host_header_value(host, port, use_tls):
    if not host:
        return None
    default = 443 if use_tls else 80
    return host if port == default else f"{host}:{port}"


def http_get(ip, port, path, timeout, use_tls, host=None):
    """Return (status, headers_lowercase, set_cookie_list, body_text) or None."""
    try:
        if use_tls:
            conn = _SNIHTTPS(ip, port, timeout, host)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
        hv = host_header_value(host, port, use_tls)
        if hv:
            headers["Host"] = hv
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read(MAX_BODY).decode("utf-8", errors="replace")
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        cookies = [v for k, v in resp.getheaders() if k.lower() == "set-cookie"]
        status = resp.status
        conn.close()
        return status, hdrs, cookies, body
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return None


def get_following_redirects(ip, port, path, timeout, use_tls, host, max_hops=3):
    """Follow redirects that stay on the same host/IP; return (final_response, final_path)."""
    result = http_get(ip, port, path, timeout, use_tls, host)
    hops = 0
    while result and result[0] in (301, 302, 303, 307, 308) and hops < max_hops:
        loc = result[1].get("location", "")
        if not loc:
            break
        parsed = urlparse(loc)
        if parsed.netloc and parsed.hostname not in (ip, host):
            break
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if parsed.scheme == "https":
            use_tls, port = True, (parsed.port or 443)
        elif parsed.scheme == "http":
            use_tls, port = False, (parsed.port or 80)
        result = http_get(ip, port, path, timeout, use_tls, host)
        hops += 1
    return result, path


def scan_service(ip, port, timeout, host=None, start_path="/", use_tls=None):
    if use_tls is None:
        use_tls = port in TLS_PORTS
    evidence = []

    home, final_path = get_following_redirects(ip, port, start_path, timeout, use_tls, host)
    if home is None:
        # Non-standard ports may speak the other protocol; try once
        use_tls = not use_tls
        home, final_path = get_following_redirects(ip, port, start_path, timeout, use_tls, host)
    if home is None:
        return None

    status, hdrs, cookies, body = home
    server = hdrs.get("server", "")
    powered = hdrs.get("x-powered-by", "")

    if re.search(r"\.php(?:$|[?/])", start_path, re.I) or re.search(r"\.php(?:$|[?/])", final_path, re.I):
        evidence.append(f"URL path uses .php ({final_path})")
    if PHP_HEADER_RE.search(powered):
        evidence.append(f"X-Powered-By: {powered}")
    if PHP_HEADER_RE.search(server):
        evidence.append(f"Server: {server}")
    if any("phpsessid" in c.lower() for c in cookies):
        evidence.append("PHPSESSID cookie")
    if PHP_LINK_RE.search(body):
        evidence.append("page links to .php files")

    # Baseline: what does a definitely-nonexistent .php path look like?
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    baseline = http_get(ip, port, f"/{rand}.php", timeout, use_tls, host)
    baseline_status = baseline[0] if baseline else None
    baseline_len = len(baseline[3]) if baseline else None

    for path in PROBE_PATHS:
        r = http_get(ip, port, path, timeout, use_tls, host)
        if not r:
            continue
        p_status, p_hdrs, p_cookies, p_body = r
        if path in ("/phpinfo.php", "/info.php"):
            if "PHP Version" in p_body or "phpinfo()" in p_body:
                evidence.append(f"{path} exposes phpinfo() output  <-- HIGH RISK")
                continue
        if p_status == 200 and (baseline_status != 200 or baseline_len != len(p_body)):
            if PHP_HEADER_RE.search(p_hdrs.get("x-powered-by", "")):
                evidence.append(f"{path} returns 200 with PHP header")
            elif baseline_status in (404, 403, 410):
                evidence.append(f"{path} returns 200 (nonexistent .php path returns {baseline_status})")
        if any("phpsessid" in c.lower() for c in p_cookies) and "PHPSESSID cookie" not in evidence:
            evidence.append("PHPSESSID cookie")

    scheme = "https" if use_tls else "http"
    shown_host = host or ip
    return {
        "url": f"{scheme}://{shown_host}:{port}{start_path}",
        "ip": ip,
        "host": host or "",
        "port": port,
        "scheme": scheme,
        "status": status,
        "server": server,
        "x_powered_by": powered,
        "php_detected": bool(evidence),
        "evidence": "; ".join(evidence),
    }


def ptr_name(ip):
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name and name != ip else None
    except OSError:
        return None


    """IP scan task: scan the bare IP, and optionally its PTR name as a vhost."""
def scan_ip_port(ip, port, timeout, use_ptr):
    if not port_open(ip, port, timeout):
        return []
    out = []
    r = scan_service(ip, port, timeout)
    if r:
        out.append(r)
        if use_ptr:
            name = ptr_name(ip)
            if name:
                r2 = scan_service(ip, port, timeout, host=name)
                if r2:
                    out.append(r2)
    return out


def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return None

    """URL scan. `scheme` may be None for bare hostnames (scheme guessed from port)."""
def scan_url_target(host, port, scheme, path, timeout, ports_from_bare, net, allow_outside):

    ip = resolve(host)
    if not ip:
        print(f"skip: cannot resolve {host}", file=sys.stderr)
        return []
    if net is not None and ipaddress.ip_address(ip) not in net and not allow_outside:
        print(f"skip: {host} resolves to {ip}, outside {net} (use --allow-outside to scan anyway)",
              file=sys.stderr)
        return []
    if ports_from_bare and not port_open(ip, port, timeout):
        return []
    use_tls = None if scheme is None else (scheme == "https")
    r = scan_service(ip, port, timeout, host=host, start_path=path, use_tls=use_tls)
    return [r] if r else []


def parse_url_entry(entry, ports):
    """Yield (host, port, scheme_or_None, path, from_bare) tuples for one input line."""
    entry = entry.strip()
    if "://" in entry:
        p = urlparse(entry)
        if not p.hostname:
            return
        scheme = p.scheme.lower()
        port = p.port or (443 if scheme == "https" else 80)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        yield p.hostname, port, scheme, path, False
    else:
        # bare hostname, optionally host/path
        p = urlparse("//" + entry)
        if not p.hostname:
            return
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        if p.port:
            yield p.hostname, p.port, None, path, False
        else:
            for port in ports:
                yield p.hostname, port, None, path, True


def load_urls(args):
    entries = list(args.url or [])
    if args.urls:
        try:
            with open(args.urls) as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        entries.append(line)
        except OSError as e:
            sys.exit(f"Cannot read {args.urls}: {e}")
    return entries

# Main process 
def main():
    ap = argparse.ArgumentParser(
        description="Scan a /24 you own and/or specific URLs for web services running PHP.")
    ap.add_argument("network", nargs="?", help="CIDR to sweep, e.g. 203.0.113.0/24")
    ap.add_argument("--url", action="append", help="URL or hostname to scan (repeatable)")
    ap.add_argument("--urls", metavar="FILE", help="file with one URL/hostname per line")
    ap.add_argument("--ptr", action="store_true",
                    help="also request each live IP using its reverse-DNS (PTR) name as the Host")
    ap.add_argument("--allow-outside", action="store_true",
                    help="scan URLs even if they resolve outside the given network")
    ap.add_argument("--ports", default=",".join(map(str, DEFAULT_PORTS)),
                    help="ports for IP sweeps and bare hostnames (default: %(default)s)")
    ap.add_argument("--threads", type=int, default=64, help="concurrent workers (default: 64)")
    ap.add_argument("--timeout", type=float, default=4.0, help="per-request timeout in seconds")
    ap.add_argument("--csv", help="write all discovered web services to this CSV file")
    ap.add_argument("--all", action="store_true", help="print every web service, not just PHP hits")
    args = ap.parse_args()

    if not args.network and not args.url and not args.urls:
        ap.error("provide a network, --url, or --urls")

    net = None
    if args.network:
        try:
            net = ipaddress.ip_network(args.network, strict=False)
        except ValueError as e:
            sys.exit(f"Invalid network: {e}")
        if net.version != 4 or net.prefixlen < 24:
            sys.exit("Network sweeps are intentionally limited to a single IPv4 /24 (or smaller).")

    try:
        ports = [int(p) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        sys.exit("--ports must be a comma-separated list of integers")

    jobs = []  # (callable, args)
    if net:
        for h in net.hosts():
            for port in ports:
                jobs.append((scan_ip_port, (str(h), port, args.timeout, args.ptr)))
    url_entries = load_urls(args)
    seen_targets = set()
    for entry in url_entries:
        for host, port, scheme, path, bare in parse_url_entry(entry, ports):
            key = (host.lower(), port, scheme, path)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            jobs.append((scan_url_target,
                         (host, port, scheme, path, args.timeout, bare, net, args.allow_outside)))

    print(f"Running {len(jobs)} scan tasks "
          f"({len(url_entries)} URL entries{', ' + str(net) if net else ''}) ...", file=sys.stderr)

    results, seen = [], set()
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(fn, *a) for fn, a in jobs]
        for fut in as_completed(futures):
            try:
                rs = fut.result()
            except Exception as e:  # keep scanning on unexpected errors
                print(f"error: {e}", file=sys.stderr)
                continue
            for r in rs:
                k = (r["url"], r["ip"])
                if k not in seen:
                    seen.add(k)
                    results.append(r)

    results.sort(key=lambda r: (ipaddress.ip_address(r["ip"]), r["port"], r["host"]))

    php_hits = [r for r in results if r["php_detected"]]
    for r in (results if args.all else php_hits):
        tag = "PHP " if r["php_detected"] else "    "
        via = f" (ip {r['ip']})" if r["host"] else ""
        print(f"[{tag}] {r['url']}{via}  status={r['status']}  server={r['server'] or '-'}")
        if r["evidence"]:
            for item in r["evidence"].split("; "):
                print(f"         - {item}")

    print(f"\n{len(results)} web service(s) found, {len(php_hits)} with PHP indicators.")
    print("Note: absence of indicators does not prove PHP is absent (headers can be "
          "stripped, and name-based vhosts may not answer on a bare IP).")

    if args.csv:
        fields = ["url", "ip", "host", "port", "scheme", "status", "server",
                  "x_powered_by", "php_detected", "evidence"]
        with open(args.csv, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            w.writerows(results)
        print(f"Wrote {args.csv}")


if __name__ == "__main__":
    main()

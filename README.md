# php_scan

A small, dependency-free Python tool that fingerprints web services for PHP. Point it at a single IPv4 /24 your organization owns, at specific URLs or hostnames, or both.

It only sends ordinary HTTP/HTTPS GET requests. It does not exploit anything.

> **Authorization required.** Only scan address space and websites your organization owns or is explicitly authorized to test. Let your security team (and, where relevant, your ISP or hosting provider) know before a sweep, since it may trigger IDS alerts.

## Requirements

- Python 3.7+
- No third-party packages (standard library only)

## Quick start

```bash
# Sweep a /24
python3 php_scan.py 203.0.113.0/24

# Scan a single URL
python3 php_scan.py --url https://app.example.com/login

# Scan a list of URLs / hostnames
python3 php_scan.py --urls urls.txt

# Everything at once, with reverse-DNS vhost probing and CSV output
python3 php_scan.py 203.0.113.0/24 --urls urls.txt --ptr --csv results.csv
```

## Options

| Option | Description |
|---|---|
| `network` | IPv4 CIDR to sweep, e.g. `203.0.113.0/24`. Limited to a /24 or smaller. |
| `--url URL` | URL or hostname to scan. Repeatable. |
| `--urls FILE` | File with one URL or hostname per line. |
| `--ptr` | Also request each live IP using its reverse-DNS (PTR) name as the `Host` header. |
| `--allow-outside` | Scan URLs even if they resolve outside the given network. |
| `--ports PORTS` | Comma-separated ports for sweeps and bare hostnames. Default: `80,443,8080,8443`. |
| `--threads N` | Concurrent workers. Default: `64`. |
| `--timeout SECONDS` | Per-request timeout. Default: `4.0`. |
| `--csv FILE` | Write every discovered web service to a CSV file. |
| `--all` | Print every web service found, not just those with PHP indicators. |

At least one of `network`, `--url`, or `--urls` is required.

## URL list format

One entry per line. `#` starts a comment.

```text
# Full URL: scanned on its own port, starting at its own path
https://app.example.com/portal/

# Bare hostname: tried on every port in --ports
www.example.com

# Hostname with explicit port
intranet.example.com:8080

# Hostname with path
shop.example.com/store/
```

URLs are requested with the correct `Host` header and TLS SNI, so name-based virtual hosts are scanned properly.

If you supply both a network and URLs, any URL that resolves **outside** that network is skipped (with a note on stderr) unless `--allow-outside` is set. This stops a stray entry, such as a subdomain pointing at a CDN or SaaS provider, from sending probes at infrastructure you don't own.

## What it looks for

| Signal | Example |
|---|---|
| `X-Powered-By` header mentioning PHP | `X-Powered-By: PHP/8.1.2` |
| `Server` header mentioning PHP | `Apache/2.4.52 PHP/8.1.2` |
| `PHPSESSID` cookie | `Set-Cookie: PHPSESSID=...` |
| Links or forms pointing at `.php` files | `<a href="/login.php">` |
| Starting URL path uses `.php` | `https://example.com/index.php` |
| Probe paths respond differently from a random nonexistent `.php` path | `/index.php`, `/phpinfo.php`, `/info.php` |
| Exposed `phpinfo()` output | Flagged as **HIGH RISK** |

The nonexistent-path baseline filters out catch-all servers and soft-404 pages that return 200 for everything.

Redirects are followed up to 3 hops, but only when they stay on the same host or IP.

## Example output

```text
Running 1020 scan tasks (3 URL entries, 203.0.113.0/24) ...
[PHP ] https://203.0.113.17:443/  status=200  server=Apache/2.4.52 (Ubuntu)
         - X-Powered-By: PHP/8.1.2
         - PHPSESSID cookie
[PHP ] https://portal.example.com:443/login.php (ip 203.0.113.42)  status=200  server=nginx
         - URL path uses .php (/login.php)
         - /phpinfo.php exposes phpinfo() output  <-- HIGH RISK

12 web service(s) found, 2 with PHP indicators.
```

## CSV columns

`url`, `ip`, `host`, `port`, `scheme`, `status`, `server`, `x_powered_by`, `php_detected`, `evidence`

## Limitations

- **No hit is not proof of absence.** Headers are often stripped, and PHP can hide behind clean URLs and a reverse proxy.
- **Name-based vhosts** may not answer on a bare IP. Use `--urls` with known hostnames, or `--ptr`, to reach them.
- **HTTP/HTTPS only.** It does not detect PHP-FPM or other non-web services.
- **Certificate verification is disabled** so that self-signed and internal certificates can be scanned. Don't use it to judge certificate health.
- **IPv4 only**, and sweeps are capped at a /24 by design.

## Responsible use

This tool is intended for inventory and hygiene work on assets you are authorized to assess, for example finding forgotten PHP installs or exposed `phpinfo()` pages. Don't point it at third-party systems.

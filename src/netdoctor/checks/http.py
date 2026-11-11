"""HTTP: status, redirect chain, headers, HSTS, proxy behaviour (407, CONNECT
refusals), who generated an error (origin vs proxy), clock skew, and captive
portal detection."""

from __future__ import annotations

import email.utils
import re
import ssl
import time
import urllib.parse
from datetime import datetime, timezone

import httpx

from .. import __version__
from ..context import RunContext
from ..models import CheckResult, Status, Table
from ..netutil import IS_WINDOWS, fmt_ms, registrable_domain, same_site
from ..proxyprobe import ProxyTunnelError, connect_tunnel, proxy_get

ID = "http"
LAYER = "L7 HTTP"
TITLE = "HTTP response, redirects, proxy, captive portal"

UA = f"Mozilla/5.0 (compatible; NetDoctor/{__version__})"
MAX_REDIRECTS = 10
BODY_LIMIT = 65536
SHOW_HEADERS = ["server", "via", "x-cache", "cf-ray", "x-amz-cf-id", "x-served-by", "x-azure-ref", "content-type",
                "content-length", "location", "strict-transport-security", "alt-svc", "x-squid-error",
                "proxy-authenticate", "www-authenticate", "retry-after", "date"]
CDN_HEADERS = [("cf-ray", "Cloudflare"), ("x-amz-cf-id", "Amazon CloudFront"), ("x-fastly-request-id", "Fastly"),
               ("x-served-by", "Fastly/Varnish"), ("x-azure-ref", "Azure Front Door"), ("x-akamai-transformed", "Akamai")]
PORTAL_WORDS = re.compile(r"login|logon|portal|captive|hotspot|splash|guest|wifi|auth|terms|accept", re.I)
BLOCK_WORDS = re.compile(r"blocked|access denied|not allowed|policy|zscaler|forbidden by", re.I)


def parse_hsts(value: str | None) -> dict | None:
    if not value:
        return None
    out: dict = {"max_age": None, "include_subdomains": False, "preload": False}
    for part in value.split(";"):
        p = part.strip().lower()
        if p.startswith("max-age="):
            try:
                out["max_age"] = int(p.split("=", 1)[1].strip().strip('"'))
            except ValueError:
                pass
        elif p == "includesubdomains":
            out["include_subdomains"] = True
        elif p == "preload":
            out["preload"] = True
    return out


def title_of(body: bytes) -> str | None:
    m = re.search(rb"<title[^>]*>(.*?)</title>", body[:BODY_LIMIT], re.I | re.S)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1).decode("utf-8", errors="replace")).strip()[:120] or None


def auth_schemes(values: list[str]) -> list[str]:
    schemes = []
    for v in values:
        for part in re.split(r",\s*(?=[A-Za-z]+(?:\s|$))", v):
            name = part.strip().split(" ")[0]
            if name and name not in schemes:
                schemes.append(name)
    return schemes


def is_captive_redirect(original_host: str, location: str | None) -> bool:
    """A redirect off-site to an IP literal or to a page that looks like a login/portal."""
    if not location:
        return False
    loc = urllib.parse.urlsplit(location)
    if not loc.hostname or same_site(loc.hostname, original_host):
        return False
    if re.fullmatch(r"[\d.]+", loc.hostname):
        return True
    return bool(PORTAL_WORDS.search(loc.hostname + loc.path + "?" + loc.query))


def skew_seconds(date_header: str | None) -> float | None:
    if not date_header:
        return None
    try:
        server = email.utils.parsedate_to_datetime(date_header)
    except (TypeError, ValueError):
        return None
    if server.tzinfo is None:
        server = server.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - server).total_seconds()


def _fetch(client: httpx.Client, url: str, extensions: dict | None = None, headers: dict | None = None) -> dict:
    started = time.perf_counter()
    with client.stream("GET", url, extensions=extensions or {}, headers=headers or {}) as resp:
        body = b""
        for chunk in resp.iter_bytes():
            body += chunk
            if len(body) >= BODY_LIMIT:
                break
        ms = (time.perf_counter() - started) * 1000.0
        return {
            "url": url,
            "status": resp.status_code,
            "reason": resp.reason_phrase,
            "http_version": resp.http_version,
            "ms": ms,
            "headers": [(k, v) for k, v in resp.headers.multi_items()],
            "location": resp.headers.get("location"),
            "body": body,
        }


def _hdr(entry: dict, name: str) -> str | None:
    return next((v for k, v in entry["headers"] if k.lower() == name), None)


def _hdrs(entry: dict, name: str) -> list[str]:
    return [v for k, v in entry["headers"] if k.lower() == name]


def generated_by_proxy(entry: dict, proxied: bool) -> str | None:
    """Was this response made by a forward proxy rather than the origin? Returns a reason."""
    squid = _hdr(entry, "x-squid-error")
    if squid:
        return f"X-Squid-Error: {squid}"
    server = (_hdr(entry, "server") or "").lower()
    if any(v in server for v in ("zscaler", "squid", "bluecoat", "proxysg", "netskope")):
        return f"Server: {_hdr(entry, 'server')}"
    if proxied and entry["status"] >= 400 and _hdr(entry, "via") and not _hdr(entry, "server"):
        return f"Via: {_hdr(entry, 'via')} and no origin Server header"
    return None


def run(ctx: RunContext) -> CheckResult:
    r = CheckResult(ID, LAYER, TITLE)
    t = ctx.target
    proxy_flag = f" -x {ctx.proxy.proxy_url}" if ctx.proxied and ctx.proxy else ""
    if t.url:
        r.commands = [f"curl{'.exe' if IS_WINDOWS else ''} -v -L --max-redirs {MAX_REDIRECTS}{proxy_flag} {t.url}"]
        if IS_WINDOWS:
            r.commands.append(f"Invoke-WebRequest -Uri {t.url} -MaximumRedirection 0 -UseBasicParsing")
    if not t.is_web:
        return r.skip(f"{t.endpoint} is not an HTTP(S) target")
    if not ctx.ip and not ctx.proxied:
        return r.skip("No IP address to connect to (DNS failed)")
    tcp = ctx.result("tcp")
    if tcp and not ctx.proxied and tcp.data.get("direct", {}).get("state") not in ("open", "intermittent", None):
        return r.skip(f"TCP port {t.port} is not open")

    # 1. If a proxy is in play, ask it ourselves first: libraries hide its answer.
    if ctx.proxied and ctx.proxy:
        if not _probe_proxy(ctx, r):
            _captive(ctx, r, None)
            r.summary = next(f.message for f in r.findings if f.status in (Status.FAIL, Status.WARN))
            return r

    # 2. Follow the redirect chain by hand.
    tls = ctx.result("tls")
    insecure = bool(tls and tls.status == Status.FAIL)
    chain, error = _follow(ctx, insecure)
    if error and not chain and not insecure and "CERTIFICATE_VERIFY_FAILED" in error:
        insecure = True
        chain, error = _follow(ctx, insecure)
    if insecure:
        r.evidence.append("TLS certificate verification was disabled for these requests (like curl -k), to see the "
                          "HTTP layer behind the TLS problem.")
    r.data["chain"] = [{k: v for k, v in e.items() if k != "body"} for e in chain]
    if chain:
        ct = Table("Request chain", ["#", "URL", "Status", "Time", "Location"])
        for i, e in enumerate(chain, 1):
            ct.rows.append([str(i), e["url"], f"{e['status']} {e['reason']}", fmt_ms(e["ms"]), e["location"] or ""])
        r.tables.append(ct)
    if error:
        r.add(*_classify_error(error, ctx))
        if not chain:
            _captive(ctx, r, None)
            r.summary = next((f.message for f in r.findings if f.status in (Status.FAIL, Status.WARN)), r.findings[0].message)
            return r

    final = chain[-1]
    _classify_final(ctx, r, final, chain)
    _headers(ctx, r, final, chain)
    _captive(ctx, r, chain)
    r.summary = next((f.message for f in r.findings if f.status in (Status.FAIL, Status.WARN)),
                     next((f.message for f in r.findings if f.code == "http.ok"), r.findings[0].message if r.findings else ""))
    return r


def _probe_proxy(ctx: RunContext, r: CheckResult) -> bool:
    """Raw CONNECT/GET through the proxy. Returns True if the proxy lets us through."""
    t, proxy = ctx.target, ctx.proxy
    assert proxy is not None
    try:
        if t.scheme == "https":
            sock, resp = connect_tunnel(proxy, t.host, t.port, timeout=10.0)
            sock.close()
        else:
            resp = proxy_get(proxy, t.url or "", timeout=10.0)
    except ProxyTunnelError as exc:
        resp = exc.response
    except OSError as exc:
        r.add("http.proxy_unreachable", Status.FAIL, f"Cannot talk to the proxy {proxy.proxy_url}: {exc}")
        return False
    r.data["proxy_probe"] = resp.to_dict()
    method = "CONNECT" if t.scheme == "https" else "GET"
    pt = Table(f"Proxy answer to {method}", ["Proxy", "Status", "Key headers"])
    keys = [f"{k}: {v}" for k, v in resp.headers if k.lower() in ("proxy-authenticate", "via", "server", "x-squid-error")]
    pt.rows.append([proxy.proxy_url or "", f"{resp.status} {resp.reason}", "; ".join(keys)[:200]])
    r.tables.append(pt)
    if resp.status == 407:
        schemes = auth_schemes(resp.all("proxy-authenticate"))
        r.add("http.proxy_auth_required", Status.FAIL,
              f"The proxy {proxy.proxy_url} demands authentication (407 Proxy Authentication Required; "
              f"schemes offered: {', '.join(schemes) or 'none listed'}). The client sent no or wrong credentials, or "
              "cannot do this scheme (e.g. NTLM/Kerberos from a non-domain app). Fix: configure proxy credentials, "
              "use a proxy path with transparent auth, or exempt this app/domain from proxy authentication.")
        return False
    if t.scheme == "https" and not 200 <= resp.status < 300:
        page = title_of(resp.body)
        if resp.status in (502, 503, 504):
            r.add("http.proxy_upstream_error", Status.FAIL,
                  f"The proxy accepted us but could not reach {t.endpoint} ({resp.status} {resp.reason}"
                  + (f", {resp.header('x-squid-error')}" if resp.header("x-squid-error") else "") + ").")
        else:
            r.add("http.proxy_denied", Status.FAIL,
                  f"The proxy refused the CONNECT to {t.endpoint}: {resp.status} {resp.reason}"
                  + (f" (page: '{page}')" if page else "") + ". Usually a URL-filtering/policy block.")
        return False
    r.add("http.proxy_ok", Status.PASS, f"The proxy accepted the {method} ({resp.status} {resp.reason}).")
    return True


def _client(ctx: RunContext, insecure: bool) -> httpx.Client:
    verify: ssl.SSLContext | bool = False if insecure else ssl.create_default_context()
    return httpx.Client(
        proxy=ctx.proxy.proxy_url if ctx.proxied and ctx.proxy else None,
        verify=verify,
        timeout=httpx.Timeout(10.0, connect=8.0),
        follow_redirects=False,
        trust_env=False,
        headers={"User-Agent": UA, "Accept": "*/*"},
    )


def _follow(ctx: RunContext, insecure: bool) -> tuple[list[dict], str | None]:
    t = ctx.target
    url = t.url or ""
    chain: list[dict] = []
    seen: set[str] = set()
    # If the OS resolver failed but another resolver gave us an IP, pin the first
    # request to that IP (keeping Host and SNI) so we can see whether DNS is the only problem.
    pin = not ctx.addresses and ctx.ip and not ctx.proxied
    try:
        with _client(ctx, insecure) as client:
            for _ in range(MAX_REDIRECTS + 1):
                if url in seen:
                    return chain, f"redirect loop: {url} visited twice"
                seen.add(url)
                if pin and not chain:
                    parts = urllib.parse.urlsplit(url)
                    ip_url = parts._replace(netloc=f"{ctx.ip}:{t.port}").geturl()
                    entry = _fetch(client, ip_url, extensions={"sni_hostname": t.host}, headers={"Host": t.host})
                    entry["url"] = url + f"  (pinned to {ctx.ip})"
                else:
                    entry = _fetch(client, url)
                chain.append(entry)
                if entry["status"] in (301, 302, 303, 307, 308) and entry["location"]:
                    url = urllib.parse.urljoin(url, entry["location"])
                    continue
                return chain, None
        return chain, f"more than {MAX_REDIRECTS} redirects"
    except httpx.HTTPError as exc:
        return chain, f"{type(exc).__name__}: {exc}"


def _classify_error(error: str, ctx: RunContext) -> tuple[str, Status, str]:
    if error.startswith("redirect loop"):
        return "http.redirect_loop", Status.FAIL, f"Redirect loop: {error.split(': ', 1)[1]} (cookie/HTTPS-redirect misconfiguration)."
    if error.startswith("more than"):
        return "http.too_many_redirects", Status.FAIL, f"More than {MAX_REDIRECTS} redirects."
    if "407" in error:
        return "http.proxy_auth_required", Status.FAIL, f"The proxy demands authentication: {error}"
    if "Timeout" in error.split(":")[0]:
        return "http.timeout", Status.FAIL, f"No HTTP response in time ({error}); the server or a middlebox is not answering."
    if "CERTIFICATE_VERIFY_FAILED" in error:
        return "http.tls_error", Status.FAIL, f"The HTTPS request failed certificate verification: {error[:200]}"
    return "http.request_failed", Status.FAIL, f"HTTP request failed: {error[:200]}"


def _classify_final(ctx: RunContext, r: CheckResult, final: dict, chain: list[dict]) -> None:
    s = final["status"]
    hops = len(chain) - 1
    after = f" after {hops} redirect{'s' if hops != 1 else ''}" if hops else ""
    proxy_reason = generated_by_proxy(final, ctx.proxied)
    page = title_of(final["body"])
    server = _hdr(final, "server")
    origin = f" (Server: {server})" if server else ""
    r.data["final"] = {"url": final["url"], "status": s, "reason": final["reason"], "server": server,
                       "generated_by_proxy": proxy_reason, "title": page, "redirects": hops,
                       "location": final["location"]}
    if 200 <= s < 300:
        r.add("http.ok", Status.PASS, f"HTTP {s} {final['reason']} from {final['url']}{after} in {fmt_ms(final['ms'])}.")
    elif 300 <= s < 400:
        r.add("http.redirect_unfollowed", Status.WARN, f"HTTP {s} without a usable Location header.")
    elif s == 401:
        r.add("http.auth_required", Status.WARN,
              f"HTTP 401: the site wants authentication ({', '.join(auth_schemes(_hdrs(final, 'www-authenticate'))) or 'scheme not given'}). "
              "The network path works.")
    elif s == 403:
        body_text = final["body"][:BODY_LIMIT].decode("utf-8", errors="replace")
        if proxy_reason or BLOCK_WORDS.search(page or "") or "zscaler" in body_text.lower():
            r.add("http.blocked_by_proxy", Status.FAIL,
                  f"HTTP 403 generated by a proxy/security gateway ({proxy_reason or 'block page'}"
                  + (f", page '{page}'" if page else "") + "): blocked by URL-filtering or policy.")
        else:
            r.add("http.forbidden", Status.WARN,
                  f"HTTP 403 Forbidden from the origin{origin}: a WAF, geo/IP restriction or missing permission. "
                  "The network path works.")
    elif s == 404:
        r.add("http.not_found", Status.WARN, f"HTTP 404: {final['url']} does not exist on the server. The network path works.")
    elif s == 407:
        schemes = auth_schemes(_hdrs(final, "proxy-authenticate"))
        r.add("http.proxy_auth_required", Status.FAIL,
              f"HTTP 407 Proxy Authentication Required (schemes: {', '.join(schemes) or 'none listed'}): the proxy "
              "wants credentials the client did not send.")
    elif s == 429:
        r.add("http.rate_limited", Status.WARN, f"HTTP 429 Too Many Requests (Retry-After: {_hdr(final, 'retry-after') or '-'}).")
    elif s == 502:
        if proxy_reason:
            r.add("http.bad_gateway", Status.FAIL,
                  f"HTTP 502 from the forward proxy ({proxy_reason}): the proxy could not get a valid answer from the "
                  "origin server.")
        else:
            r.add("http.bad_gateway", Status.FAIL,
                  f"HTTP 502 Bad Gateway from the site's front end{origin}: its upstream/backend application is down or "
                  "returned an invalid response. DNS, routing, TCP and TLS to the site all work; this is a server-side "
                  "problem for the application owner.")
    elif s == 503:
        r.add("http.unavailable", Status.FAIL,
              f"HTTP 503 Service Unavailable{origin}: overloaded or in maintenance (Retry-After: {_hdr(final, 'retry-after') or '-'}).")
    elif s == 504:
        r.add("http.gateway_timeout", Status.FAIL,
              f"HTTP 504 Gateway Timeout{origin}: the front end gave up waiting for its backend.")
    elif s >= 500:
        r.add("http.server_error", Status.FAIL, f"HTTP {s} {final['reason']}{origin}: a server-side error.")
    else:
        r.add("http.client_error", Status.WARN, f"HTTP {s} {final['reason']}.")
    if page:
        r.evidence.append(f"Page title: '{page}'.")


def _headers(ctx: RunContext, r: CheckResult, final: dict, chain: list[dict]) -> None:
    ht = Table("Response headers (final)", ["Header", "Value"])
    for k, v in final["headers"]:
        if k.lower() in SHOW_HEADERS:
            ht.rows.append([k, v[:120]])
    if ht.rows:
        r.tables.append(ht)
    for header, cdn in CDN_HEADERS:
        if _hdr(final, header):
            r.evidence.append(f"Served through {cdn} ({header}: {_hdr(final, header)[:40]}).")
            break
    https_entries = [e for e in chain if e["url"].startswith("https://")]
    if https_entries:
        hsts = parse_hsts(_hdr(https_entries[-1], "strict-transport-security"))
        r.data["hsts"] = hsts
        if hsts:
            r.evidence.append(f"HSTS: max-age={hsts['max_age']}"
                              + ("; includeSubDomains" if hsts["include_subdomains"] else "")
                              + ("; preload" if hsts["preload"] else "")
                              + " (browsers will refuse plain HTTP and certificate click-through for this host).")
        else:
            r.add("http.no_hsts", Status.INFO, "No Strict-Transport-Security header on the HTTPS response.")
    skew = skew_seconds(_hdr(final, "date"))
    r.data["clock_skew_s"] = skew
    if skew is not None and abs(skew) > 300:
        direction = "ahead of" if skew > 0 else "behind"
        r.add("http.clock_skew", Status.WARN,
              f"This device's clock is {abs(skew) / 60:.0f} minutes {direction} the server's Date header. "
              "Certificate validity checks and Kerberos (5-minute tolerance) break with skew like this.")


def _captive(ctx: RunContext, r: CheckResult, chain: list[dict] | None) -> None:
    """Captive portals hijack plain HTTP. Look for it two ways: the OS-vendor style probe
    URLs, and an off-site redirect on http://<target>/."""
    t = ctx.target
    signals: list[tuple[str, str | None]] = []  # (what we saw, where it sent us)
    results = []
    with _client(ctx, insecure=True) as client:
        for url, want_status, want_body in ctx.opts.captive_probes:
            try:
                e = _fetch(client, url)
            except httpx.HTTPError as exc:
                results.append([url, "unreachable", type(exc).__name__])
                continue
            body = e["body"].decode("utf-8", errors="replace")
            ok = e["status"] == want_status and (want_body is None or want_body in body)
            note = "expected" if ok else (e["location"] or title_of(e["body"]) or "unexpected content")
            results.append([url, f"{e['status']} {e['reason']}", note])
            if not ok:
                signals.append((f"probe {url} returned {e['status']} instead of {want_status}", e["location"]))
        if t.scheme == "https" and not ctx.proxied:
            plain = f"http://{t.url_host}/"
            try:
                e = _fetch(client, plain)
                results.append([plain, f"{e['status']} {e['reason']}", e["location"] or ""])
                if e["status"] in (301, 302, 303, 307, 308) and is_captive_redirect(t.host, e["location"]):
                    signals.append((f"{plain} redirects off-site", e["location"]))
            except httpx.HTTPError as exc:
                results.append([plain, "unreachable", type(exc).__name__])
    if chain and t.scheme == "http":
        first = chain[0]
        if first["status"] in (301, 302, 303, 307, 308) and is_captive_redirect(t.host, first["location"]):
            signals.append((f"{first['url']} redirects off-site", first["location"]))
    r.tables.append(Table("Captive-portal probes", ["URL", "Result", "Note"], results))
    r.data["captive"] = {"signals": [s for s, _ in signals], "probes": results}
    if signals:
        portal = next((loc for _s, loc in signals if loc), None)
        host = urllib.parse.urlsplit(portal).hostname if portal else None
        r.add("http.captive_portal", Status.FAIL,
              "Captive portal: plain-HTTP requests are intercepted and redirected"
              + (f" to {registrable_domain(host)} ({portal})" if host else "")
              + f" [{'; '.join(s for s, _ in signals)}]. The user must log in or accept terms on the portal page; "
              "until then HTTPS fails with certificate errors or timeouts.")

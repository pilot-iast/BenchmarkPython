#!/usr/bin/env python3
"""OWASP Benchmark HTTP crawler (Python port of BenchmarkUtils ServletTestCaseRequest)."""

from __future__ import annotations

import argparse
import socket
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import requests
import urllib3
from requests.exceptions import InvalidHeader

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@dataclass
class RequestVariable:
    name: str
    value: str
    attack_name: str | None = None
    attack_value: str | None = None
    safe_name: str | None = None
    safe_value: str | None = None
    use_safe: bool = True

    def resolved(self) -> tuple[str, str]:
        if self.use_safe:
            if self.safe_name is not None and self.safe_value is not None:
                return self.safe_name, self.safe_value
            return self.name, self.value
        if self.attack_name is not None and self.attack_value is not None:
            return self.attack_name, self.attack_value
        return self.name, self.value


@dataclass
class BenchmarkTest:
    name: str
    url: str
    cookies: list[RequestVariable] = field(default_factory=list)
    form_params: list[RequestVariable] = field(default_factory=list)
    get_params: list[RequestVariable] = field(default_factory=list)
    headers: list[RequestVariable] = field(default_factory=list)


def parse_crawler_xml(path: Path) -> list[BenchmarkTest]:
    root = ET.parse(path).getroot()
    tests: list[BenchmarkTest] = []
    for node in root.findall("benchmarkTest"):
        name = node.get("tcName") or ""
        url = node.get("URL") or ""
        if not name or not url:
            continue
        test = BenchmarkTest(name=name, url=url)
        for child in node:
            tag = child.tag
            var = RequestVariable(
                name=child.get("name") or "",
                value=child.get("value") or "",
                attack_name=child.get("attackName"),
                attack_value=child.get("attackValue"),
                safe_name=child.get("safeName"),
                safe_value=child.get("safeValue"),
            )
            if tag == "cookie":
                test.cookies.append(var)
            elif tag == "formparam":
                test.form_params.append(var)
            elif tag == "getparam":
                test.get_params.append(var)
            elif tag == "header":
                test.headers.append(var)
        tests.append(test)
    tests.sort(key=lambda item: item.name)
    return tests


def rewrite_base_url(url: str, base_url: str | None) -> str:
    if not base_url:
        return url
    parsed = urlsplit(url)
    base = urlsplit(base_url.rstrip("/"))
    return urlunsplit((base.scheme, base.netloc, parsed.path, parsed.query, parsed.fragment))


def encode_cookie_value(value: str) -> str:
    return quote(value, safe="").replace("+", "%20")


def send_raw_http(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    *,
    timeout: float,
) -> int:
    """Send HTTP(S) without urllib3 header validation (matches Java HttpClient behavior)."""
    parsed = urlsplit(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    header_lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    for key, value in headers.items():
        if key.lower() == "host":
            continue
        header_lines.append(f"{key}: {value}")
    if body:
        header_lines.append(f"Content-Length: {len(body)}")
    header_lines.extend(["Connection: close", ""])
    payload = "\r\n".join(header_lines).encode("latin-1", errors="replace") + body

    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.sendall(payload)
        response = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk
    finally:
        sock.close()

    status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return 0


def build_request(test: BenchmarkTest) -> tuple[str, str, dict[str, str], dict[str, str], dict[str, str]]:
    query = ""
    if test.get_params:
        pairs = [var.resolved() for var in test.get_params]
        query = "?" + urlencode(pairs)

    url = test.url + query
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    for var in test.headers:
        key, value = var.resolved()
        headers[key] = value

    cookie_parts = []
    for var in test.cookies:
        key, value = var.resolved()
        cookie_parts.append(f"{key}={encode_cookie_value(value)}")
    if cookie_parts:
        headers["Cookie"] = "; ".join(cookie_parts)

    data = {key: value for key, value in (var.resolved() for var in test.form_params)}
    method = "GET" if test.get_params else "POST"
    return method, url, headers, data, {}


def execute_request(
    session: requests.Session,
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    data: dict[str, str],
    timeout: float,
) -> int:
    body = urlencode(data).encode("utf-8") if data else b""
    try:
        if method == "GET":
            response = session.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
            )
        else:
            response = session.post(
                url,
                headers=headers,
                data=data,
                timeout=timeout,
                allow_redirects=False,
            )
        return response.status_code
    except (InvalidHeader, ValueError) as exc:
        if "header" not in str(exc).lower():
            raise
        return send_raw_http(method, url, headers, body, timeout=timeout)


def crawl(
    tests: list[BenchmarkTest],
    *,
    base_url: str | None,
    proxy_host: str | None,
    proxy_port: int | None,
    timeout: float,
    failed_log: Path | None,
) -> tuple[int, int]:
    session = requests.Session()
    session.verify = False
    if proxy_host and proxy_port:
        proxy = f"http://{proxy_host}:{proxy_port}"
        session.proxies.update({"http": proxy, "https": proxy})

    ok = 0
    failed = 0
    failures: list[str] = []
    for test in tests:
        method, url, headers, data, _ = build_request(test)
        url = rewrite_base_url(url, base_url)
        display_url = url.split("?", 1)[0] + ("?***" if "?" in url else "")
        try:
            status = execute_request(
                session,
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=timeout,
            )
            print(f"{method} {display_url} --> ({status})")
            if status >= 400:
                failed += 1
                failures.append(f"{test.name}\t{status}\t{method} {display_url}")
            else:
                ok += 1
        except (requests.RequestException, OSError) as exc:
            failed += 1
            failures.append(f"{test.name}\tERROR\t{method} {display_url}\t{exc}")
            print(f"{method} {display_url} --> ERROR {exc}", file=sys.stderr)
    if failed_log and failures:
        failed_log.write_text("\n".join(failures) + "\n", encoding="utf-8")
    return ok, failed


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--crawler-file",
        default=str(root / "data" / "benchmark-crawler-http.xml"),
        help="Benchmark crawler XML",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="Replace scheme/host in XML URLs (e.g. https://127.0.0.1:8443)",
    )
    parser.add_argument("--proxy-host", default="")
    parser.add_argument("--proxy-port", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--failed-log",
        default="",
        help="Write failed test names and reasons to this file",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any crawl request failed (default: tolerate partial failures)",
    )
    args = parser.parse_args()

    crawler_file = Path(args.crawler_file)
    if not crawler_file.is_file():
        print(f"Crawler file not found: {crawler_file}", file=sys.stderr)
        return 2

    tests = parse_crawler_xml(crawler_file)
    if not tests:
        print("No benchmark tests found in crawler XML", file=sys.stderr)
        return 2

    proxy_host = args.proxy_host or None
    proxy_port = args.proxy_port or None
    base_url = args.base_url or None

    started = time.time()
    failed_log = Path(args.failed_log) if args.failed_log else None
    ok, failed = crawl(
        tests,
        base_url=base_url,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        timeout=args.timeout,
        failed_log=failed_log,
    )
    elapsed = int(time.time() - started)
    print(
        f"Crawl finished: {len(tests)} tests, ok={ok}, failed={failed}, took {elapsed}s"
    )
    if args.strict and failed:
        return 1
    if failed and ok == 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

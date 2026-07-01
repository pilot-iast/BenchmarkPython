#!/usr/bin/env python3
"""OWASP Benchmark HTTP crawler (Python port of BenchmarkUtils ServletTestCaseRequest)."""

from __future__ import annotations

import argparse
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, urlencode, urlsplit, urlunsplit

import requests
import urllib3

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


def crawl(
    tests: list[BenchmarkTest],
    *,
    base_url: str | None,
    proxy_host: str | None,
    proxy_port: int | None,
    timeout: float,
) -> tuple[int, int]:
    session = requests.Session()
    session.verify = False
    if proxy_host and proxy_port:
        proxy = f"http://{proxy_host}:{proxy_port}"
        session.proxies.update({"http": proxy, "https": proxy})

    ok = 0
    failed = 0
    for test in tests:
        method, url, headers, data, _ = build_request(test)
        url = rewrite_base_url(url, base_url)
        try:
            if method == "GET":
                response = session.get(url, headers=headers, timeout=timeout)
            else:
                response = session.post(url, headers=headers, data=data, timeout=timeout)
            print(f"{method} {url} --> ({response.status_code})")
            if response.status_code >= 400:
                failed += 1
            else:
                ok += 1
        except requests.RequestException as exc:
            failed += 1
            print(f"{method} {url} --> ERROR {exc}", file=sys.stderr)
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
    ok, failed = crawl(
        tests,
        base_url=base_url,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        timeout=args.timeout,
    )
    elapsed = int(time.time() - started)
    print(
        f"Crawl finished: {len(tests)} tests, ok={ok}, failed={failed}, took {elapsed}s"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

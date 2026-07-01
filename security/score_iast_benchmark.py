#!/usr/bin/env python3
"""Fetch IAST findings for a project version and score against OWASP Benchmark ground truth."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from panel_client import (
    fetch_all_vulnerabilities,
    fetch_panel_vulnerability_summary,
    find_project_id,
    list_project_agents,
    login,
    make_session,
    read_agent_properties,
    resolve_run_agent_ids,
    resolve_version_id,
)

TEST_RE = re.compile(r"BenchmarkTest\d{5}")

# Header-only findings (CSP, X-Frame-Options, etc.) are not planted benchmark cases.
_HEADER_VUL_NAMES = frozenset(
    name.lower()
    for name in (
        "Response Without Content-Security-Policy Header",
        "Response With X-XSS-Protection Disabled",
        "Response With Insecurely Configured Strict-Transport-Security Header",
        "Pages Without Anti-Clickjacking Controls",
        "Response Without X-Content-Type-Options Header",
    )
)


@dataclass
class ExpectedCase:
    name: str
    category: str
    vulnerable: bool
    cwe: str
    endpoint: str = ""


@dataclass
class Finding:
    test_name: str
    uri: str
    vul_type: str
    http_method: str
    vul_id: int | None = None


@dataclass
class CategoryScore:
    category: str
    expected_vulnerable: int
    expected_safe: int
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0

    @property
    def recall_pct(self) -> float:
        denom = self.tp + self.fn
        return (100.0 * self.tp / denom) if denom else 0.0

    @property
    def false_positive_rate_pct(self) -> float:
        denom = self.fp + self.tn
        return (100.0 * self.fp / denom) if denom else 0.0

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "expected_vulnerable": self.expected_vulnerable,
            "expected_safe": self.expected_safe,
            "tp": self.tp,
            "fn": self.fn,
            "fp": self.fp,
            "tn": self.tn,
            "recall_pct": round(self.recall_pct, 2),
            "false_positive_rate_pct": round(self.false_positive_rate_pct, 2),
        }


@dataclass
class ScoreReport:
    project_name: str
    project_version: str
    project_id: int
    version_id: int
    iast_findings_total: int
    expected_vulnerable: int
    expected_safe: int
    iast_findings_scored: int = 0
    fetch_api: str = ""
    fetch_pages: int = 0
    vuln_scope: str = "project"
    run_agent_ids: list[int] = field(default_factory=list)
    panel_type_counts: list[dict] = field(default_factory=list)
    iast_type_counts: list[dict] = field(default_factory=list)
    by_category: list[CategoryScore] = field(default_factory=list)
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    false_negatives: list[dict] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)

    @property
    def recall_pct(self) -> float:
        denom = self.tp + self.fn
        return (100.0 * self.tp / denom) if denom else 0.0

    @property
    def false_positive_rate_pct(self) -> float:
        denom = self.fp + self.tn
        return (100.0 * self.fp / denom) if denom else 0.0

    @property
    def precision_pct(self) -> float:
        denom = self.tp + self.fp
        return (100.0 * self.tp / denom) if denom else 0.0

    @property
    def f1_score(self) -> float:
        p = self.precision_pct / 100.0
        r = self.recall_pct / 100.0
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "project_name": self.project_name,
            "project_version": self.project_version,
            "project_id": self.project_id,
            "version_id": self.version_id,
            "iast_findings_total": self.iast_findings_total,
            "iast_findings_scored": self.iast_findings_scored,
            "fetch_api": self.fetch_api,
            "fetch_pages": self.fetch_pages,
            "vuln_scope": self.vuln_scope,
            "run_agent_ids": self.run_agent_ids,
            "panel_type_counts": self.panel_type_counts,
            "iast_type_counts": self.iast_type_counts,
            "by_category": [row.to_dict() for row in self.by_category],
            "expected_vulnerable": self.expected_vulnerable,
            "expected_safe": self.expected_safe,
            "tp": self.tp,
            "fn": self.fn,
            "fp": self.fp,
            "tn": self.tn,
            "recall_pct": round(self.recall_pct, 2),
            "false_positive_rate_pct": round(self.false_positive_rate_pct, 2),
            "precision_pct": round(self.precision_pct, 2),
            "f1_score": round(self.f1_score, 4),
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
        }


def load_expected(path: Path) -> dict[str, ExpectedCase]:
    cases: dict[str, ExpectedCase] = {}
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 3:
                continue
            name, category, vuln_raw = parts[0], parts[1], parts[2].lower()
            cwe = parts[3] if len(parts) > 3 else ""
            cases[name] = ExpectedCase(
                name=name,
                category=category,
                vulnerable=vuln_raw == "true",
                cwe=cwe,
            )
    return cases


def load_test_urls(crawler_xml: Path) -> dict[str, str]:
    urls: dict[str, str] = {}
    root = ET.parse(crawler_xml).getroot()
    for test in root.findall("benchmarkTest"):
        name = test.get("tcName")
        url = test.get("URL")
        if name and url:
            urls[name] = url
    return urls


def attach_endpoints(cases: dict[str, ExpectedCase], urls: dict[str, str]) -> None:
    for name, case in cases.items():
        case.endpoint = urls.get(name, "")


def extract_test_name(value: str) -> str | None:
    if not value:
        return None
    match = TEST_RE.search(value)
    return match.group(0) if match else None


def is_benchmark_noise(item: dict) -> bool:
    if item.get("is_header_vul"):
        return True
    vul_type = str(
        item.get("strategy__vul_name") or item.get("type") or item.get("vul_type") or ""
    ).strip()
    return vul_type.lower() in _HEADER_VUL_NAMES


def collect_findings(vulns: list[dict]) -> tuple[set[str], dict[str, list[Finding]]]:
    found: set[str] = set()
    by_test: dict[str, list[Finding]] = defaultdict(list)
    for item in vulns:
        if is_benchmark_noise(item):
            continue
        uri = str(item.get("uri") or item.get("url") or "")
        test_name = extract_test_name(uri) or extract_test_name(str(item.get("url") or ""))
        if not test_name:
            continue
        finding = Finding(
            test_name=test_name,
            uri=uri,
            vul_type=str(
                item.get("strategy__vul_name") or item.get("type") or item.get("vul_type") or ""
            ),
            http_method=str(item.get("http_method") or ""),
            vul_id=item.get("id"),
        )
        found.add(test_name)
        by_test[test_name].append(finding)
    return found, by_test


def score_category(
    cases: dict[str, ExpectedCase],
    found_tests: set[str],
    findings_by_test: dict[str, list[Finding]],
    category: str,
) -> CategoryScore:
    cat_cases = {name: case for name, case in cases.items() if case.category == category}
    row = CategoryScore(
        category=category,
        expected_vulnerable=sum(1 for case in cat_cases.values() if case.vulnerable),
        expected_safe=sum(1 for case in cat_cases.values() if not case.vulnerable),
    )
    false_negatives: list[dict] = []
    false_positives: list[dict] = []

    for name, case in sorted(cat_cases.items()):
        detected = name in found_tests
        if case.vulnerable and detected:
            row.tp += 1
        elif case.vulnerable and not detected:
            row.fn += 1
            false_negatives.append(
                {
                    "test": name,
                    "category": case.category,
                    "expected": "vulnerable",
                    "endpoint": case.endpoint,
                    "cwe": case.cwe,
                }
            )
        elif not case.vulnerable and detected:
            row.fp += 1
            hits = findings_by_test.get(name, [])
            false_positives.append(
                {
                    "test": name,
                    "category": case.category,
                    "expected": "safe",
                    "endpoint": case.endpoint or (hits[0].uri if hits else ""),
                    "cwe": case.cwe,
                    "iast_types": sorted({h.vul_type for h in hits if h.vul_type}),
                    "uris": sorted({h.uri for h in hits if h.uri}),
                }
            )
        else:
            row.tn += 1

    return row, false_negatives, false_positives


def score_cases(
    cases: dict[str, ExpectedCase],
    found_tests: set[str],
    findings_by_test: dict[str, list[Finding]],
    *,
    project_name: str,
    project_version: str,
    project_id: int,
    version_id: int,
    iast_findings_total: int,
) -> ScoreReport:
    report = ScoreReport(
        project_name=project_name,
        project_version=project_version,
        project_id=project_id,
        version_id=version_id,
        iast_findings_total=iast_findings_total,
        expected_vulnerable=sum(1 for c in cases.values() if c.vulnerable),
        expected_safe=sum(1 for c in cases.values() if not c.vulnerable),
    )

    categories = sorted({case.category for case in cases.values()})
    for category in categories:
        row, fns, fps = score_category(cases, found_tests, findings_by_test, category)
        report.by_category.append(row)
        report.false_negatives.extend(fns)
        report.false_positives.extend(fps)
        report.tp += row.tp
        report.fn += row.fn
        report.fp += row.fp
        report.tn += row.tn

    return report


def summarize_iast_types(vulns: list[dict]) -> list[dict]:
    counts: dict[str, int] = defaultdict(int)
    for item in vulns:
        if is_benchmark_noise(item):
            continue
        vul_type = str(
            item.get("strategy__vul_name") or item.get("type") or item.get("vul_type") or ""
        ).strip()
        if vul_type:
            counts[vul_type] += 1
    return [
        {"type": vul_type, "count": count}
        for vul_type, count in sorted(counts.items(), key=lambda row: (-row[1], row[0]))
    ]


def summarize_panel_types(summary: dict) -> list[dict]:
    rows = summary.get("hook_type") or []
    return [
        {
            "type": str(row.get("name") or ""),
            "count": int(row.get("num") or 0),
            "strategy_id": row.get("id"),
        }
        for row in sorted(rows, key=lambda item: (-int(item.get("num") or 0), str(item.get("name") or "")))
        if row.get("name")
    ]


def render_markdown(report: ScoreReport) -> str:
    lines = [
        "# OWASP Benchmark for Python × Immunity IAST scorecard",
        "",
        f"- **Project:** {report.project_name} (id={report.project_id})",
        f"- **Version:** {report.project_version} (id={report.version_id})",
        f"- **IAST findings (raw):** {report.iast_findings_total} "
        f"(scope={report.vuln_scope}, api={report.fetch_api or 'unknown'}, pages={report.fetch_pages})",
        f"- **IAST findings (scored, excl. header noise):** {report.iast_findings_scored}",
        f"- **Run agents:** {report.run_agent_ids or 'none'}",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Expected vulnerable tests | {report.expected_vulnerable} |",
        f"| Expected safe tests | {report.expected_safe} |",
        f"| True positives (TP) | {report.tp} |",
        f"| False negatives (FN) | {report.fn} |",
        f"| False positives (FP) | {report.fp} |",
        f"| True negatives (TN) | {report.tn} |",
        f"| **Recall** (found planted vulns) | **{report.recall_pct:.2f}%** |",
        f"| **False positive rate** (safe flagged) | **{report.false_positive_rate_pct:.2f}%** |",
        f"| Precision | {report.precision_pct:.2f}% |",
        f"| F1 | {report.f1_score:.4f} |",
        "",
    ]

    if report.panel_type_counts:
        lines.extend(
            [
                "## Panel vulnerability types (raw counts from UI API)",
                "",
                "| IAST type | Count |",
                "| --- | ---: |",
            ]
        )
        for row in report.panel_type_counts:
            lines.append(f"| {row['type']} | {row['count']} |")
        lines.append("")

    if report.iast_type_counts:
        lines.extend(
            [
                "## Scored findings by IAST type (excl. header noise, mapped to benchmark tests)",
                "",
                "| IAST type | Findings |",
                "| --- | ---: |",
            ]
        )
        for row in report.iast_type_counts:
            lines.append(f"| {row['type']} | {row['count']} |")
        lines.append("")

    if report.by_category:
        lines.extend(
            [
                "## Score by benchmark category",
                "",
                "| Category | Vuln tests | Safe tests | TP | FN | FP | TN | Recall | FP rate |",
                "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for row in report.by_category:
            lines.append(
                f"| {row.category} | {row.expected_vulnerable} | {row.expected_safe} | "
                f"{row.tp} | {row.fn} | {row.fp} | {row.tn} | "
                f"{row.recall_pct:.2f}% | {row.false_positive_rate_pct:.2f}% |"
            )
        lines.append("")

    def append_section(title: str, items: list[dict]) -> None:
        lines.append(f"## {title} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("_None_")
            lines.append("")
            return
        for row in items:
            endpoint = row.get("endpoint") or (row.get("uris") or ["?"])[0]
            extra = ""
            if row.get("iast_types"):
                extra = f" — IAST: {', '.join(row['iast_types'])}"
            lines.append(
                f"- `{row['test']}` ({row['category']}, {row['expected']}) "
                f"→ {endpoint}{extra}"
            )
        lines.append("")

    append_section("False negatives (missed planted vulnerabilities)", report.false_negatives)
    append_section("False positives (safe tests flagged as vulnerable)", report.false_positives)
    return "\n".join(lines)


def fetch_panel_vulnerabilities(
    panel_url: str,
    user: str,
    password: str,
    project_name: str,
    version_name: str,
    *,
    scope: str = "version",
) -> tuple[int, int, str, list[dict], list[int], dict, dict]:
    session = make_session(panel_url)
    login(session, panel_url, user, password)
    project_id = find_project_id(session, panel_url, project_name)
    version_id, resolved_version = resolve_version_id(
        session, panel_url, project_id, version_name
    )
    agents = list_project_agents(session, panel_url, project_id)
    run_agent_ids = resolve_run_agent_ids(agents, version_id)
    vulns, fetch_meta = fetch_all_vulnerabilities(
        session,
        panel_url,
        project_id,
        version_id,
        project_name=project_name,
        scope=scope,
    )
    panel_summary = fetch_panel_vulnerability_summary(
        session, panel_url, project_id, version_id
    )
    return (
        project_id,
        version_id,
        resolved_version,
        vulns,
        run_agent_ids,
        fetch_meta,
        panel_summary,
    )


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel-url", default=os.environ.get("PANEL_URL", ""))
    parser.add_argument("--user", default=os.environ.get("PANEL_USER", ""))
    parser.add_argument("--password", default=os.environ.get("PANEL_PASS", ""))
    parser.add_argument("--project-name", default="")
    parser.add_argument("--project-version", default="")
    parser.add_argument(
        "--agent-artifact",
        default=str(root / "iast-tool"),
        help="Python agent wheel/tar.gz (or directory containing one) for project name/version fallback",
    )
    parser.add_argument(
        "--expected",
        default=str(root / "expectedresults-0.1.csv"),
        help="OWASP Benchmark ground truth CSV",
    )
    parser.add_argument(
        "--crawler-xml",
        default=str(root / "data" / "benchmark-crawler-http.xml"),
        help="Benchmark crawler XML for test endpoint URLs",
    )
    parser.add_argument(
        "--vuln-scope",
        choices=("project", "version"),
        default="version",
        help="version=agents of this run (default); project=all agents ever bound to the app",
    )
    parser.add_argument("--output-json", default="scorecard-iast.json")
    parser.add_argument("--output-md", default="scorecard-iast.md")
    args = parser.parse_args()

    panel_url = (args.panel_url or os.environ.get("IAST_SERVER_URL", "")).strip()
    user = (args.user or os.environ.get("PANEL_USER", "")).strip()
    password = args.password or os.environ.get("PANEL_PASS", "")
    project_name = (args.project_name or os.environ.get("IAST_PROJECT_NAME") or "").strip()
    project_version = (args.project_version or os.environ.get("PROJECT_VERSION") or "").strip()

    agent_props = read_agent_properties(args.agent_artifact)
    if not project_name:
        project_name = agent_props.get("project.name", "").strip()
    if not project_name:
        project_name = "benchmarkpython"
    if not project_version:
        project_version = agent_props.get("project.version", "").strip()

    if not panel_url or not user or not password:
        print("Set PANEL_URL (or IAST_SERVER_URL), PANEL_USER, PANEL_PASS", file=sys.stderr)
        return 2
    if not project_version:
        print("Set PROJECT_VERSION (e.g. run-42 from agent download)", file=sys.stderr)
        return 2

    print(
        f"Panel={panel_url!r} verify_ssl={os.environ.get('PANEL_VERIFY_SSL', 'false')!r} "
        f"project={project_name!r} version={project_version!r}"
    )
    cases = load_expected(Path(args.expected))
    urls = load_test_urls(Path(args.crawler_xml))
    attach_endpoints(cases, urls)

    (
        project_id,
        version_id,
        resolved_version,
        vulns,
        run_agent_ids,
        fetch_meta,
        panel_summary,
    ) = fetch_panel_vulnerabilities(
        panel_url,
        user,
        password,
        project_name,
        project_version,
        scope=args.vuln_scope,
    )
    found_tests, findings_by_test = collect_findings(vulns)
    scored_total = sum(len(items) for items in findings_by_test.values())
    print(
        f"Fetched {len(vulns)} IAST findings for version {resolved_version!r} "
        f"(scope={args.vuln_scope}, api={fetch_meta.get('api')}, "
        f"pages={fetch_meta.get('pages_fetched')}, scored={scored_total}, "
        f"agents={run_agent_ids})"
    )
    report = score_cases(
        cases,
        found_tests,
        findings_by_test,
        project_name=project_name,
        project_version=resolved_version,
        project_id=project_id,
        version_id=version_id,
        iast_findings_total=len(vulns),
    )
    report.iast_findings_scored = scored_total
    report.fetch_api = str(fetch_meta.get("api") or "")
    report.fetch_pages = int(fetch_meta.get("pages_fetched") or 0)
    report.vuln_scope = args.vuln_scope
    report.run_agent_ids = run_agent_ids
    report.panel_type_counts = summarize_panel_types(panel_summary)
    report.iast_type_counts = summarize_iast_types(vulns)

    payload = report.to_dict()
    Path(args.output_json).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    md = render_markdown(report)
    Path(args.output_md).write_text(md, encoding="utf-8")

    print(md)
    print(f"\nWrote {args.output_json} and {args.output_md}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        import traceback

        traceback.print_exc()
        raise

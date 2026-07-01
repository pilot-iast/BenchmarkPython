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
    find_project_id,
    iter_vulnerabilities,
    list_project_agents,
    login,
    make_session,
    read_agent_properties,
    resolve_run_agent_ids,
    resolve_version_id,
)

TEST_RE = re.compile(r"BenchmarkTest\d{5}")


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
class ScoreReport:
    project_name: str
    project_version: str
    project_id: int
    version_id: int
    iast_findings_total: int
    expected_vulnerable: int
    expected_safe: int
    vuln_scope: str = "project"
    run_agent_ids: list[int] = field(default_factory=list)
    run_only_findings_total: int = 0
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
            "vuln_scope": self.vuln_scope,
            "run_agent_ids": self.run_agent_ids,
            "run_only_findings_total": self.run_only_findings_total,
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


def collect_findings(vulns: list[dict]) -> tuple[set[str], dict[str, list[Finding]]]:
    found: set[str] = set()
    by_test: dict[str, list[Finding]] = defaultdict(list)
    for item in vulns:
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

    for name, case in sorted(cases.items()):
        detected = name in found_tests
        if case.vulnerable and detected:
            report.tp += 1
        elif case.vulnerable and not detected:
            report.fn += 1
            report.false_negatives.append(
                {
                    "test": name,
                    "category": case.category,
                    "expected": "vulnerable",
                    "endpoint": case.endpoint,
                    "cwe": case.cwe,
                }
            )
        elif not case.vulnerable and detected:
            report.fp += 1
            hits = findings_by_test.get(name, [])
            report.false_positives.append(
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
            report.tn += 1

    return report


def render_markdown(report: ScoreReport) -> str:
    lines = [
        "# OWASP Benchmark for Python × Immunity IAST scorecard",
        "",
        f"- **Project:** {report.project_name} (id={report.project_id})",
        f"- **Version:** {report.project_version} (id={report.version_id})",
        f"- **IAST findings (raw):** {report.iast_findings_total} "
        f"(scope={report.vuln_scope})",
        f"- **Run-only findings (version agent filter):** {report.run_only_findings_total} "
        f"(agents={report.run_agent_ids or 'none'})",
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
    scope: str = "project",
) -> tuple[int, int, str, list[dict], list[int], int]:
    session = make_session(panel_url)
    login(session, panel_url, user, password)
    project_id = find_project_id(session, panel_url, project_name)
    version_id, resolved_version = resolve_version_id(
        session, panel_url, project_id, version_name
    )
    agents = list_project_agents(session, panel_url, project_id)
    run_agent_ids = resolve_run_agent_ids(agents, version_id)
    run_only = list(
        iter_vulnerabilities(
            session,
            panel_url,
            project_id,
            version_id,
            project_name=project_name,
            scope="version",
        )
    )
    vulns = list(
        iter_vulnerabilities(
            session,
            panel_url,
            project_id,
            version_id,
            project_name=project_name,
            scope=scope,
        )
    )
    return (
        project_id,
        version_id,
        resolved_version,
        vulns,
        run_agent_ids,
        len(run_only),
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
        default="project",
        help="project=all deduplicated findings for the app; version=only agents of this run",
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
        run_only_total,
    ) = fetch_panel_vulnerabilities(
        panel_url,
        user,
        password,
        project_name,
        project_version,
        scope=args.vuln_scope,
    )
    found_tests, findings_by_test = collect_findings(vulns)
    print(
        f"Fetched {len(vulns)} IAST findings for version {resolved_version!r} "
        f"(scope={args.vuln_scope}, run-only={run_only_total}, agents={run_agent_ids})"
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
    report.vuln_scope = args.vuln_scope
    report.run_agent_ids = run_agent_ids
    report.run_only_findings_total = run_only_total

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

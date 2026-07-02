"""Immunity IAST panel API helpers (login, projects, versions, vulnerabilities)."""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path
from typing import Iterator

import requests


def make_session(panel_url: str) -> requests.Session:
    session = requests.Session()
    session.headers["Referer"] = panel_url.rstrip("/") + "/"
    verify_env = os.environ.get("PANEL_VERIFY_SSL", "false").strip().lower()
    session.verify = verify_env in ("1", "true", "yes")
    return session


def _check_api_response(resp: requests.Response, action: str) -> dict:
    try:
        body = resp.json()
    except ValueError as exc:
        raise RuntimeError(
            f"{action} failed: HTTP {resp.status_code}, non-JSON body: {resp.text[:300]!r}"
        ) from exc
    if body.get("status") not in (201, 200):
        raise RuntimeError(f"{action} failed: {body.get('msg')} (body={body!r})")
    return body


def login(session: requests.Session, base_url: str, username: str, password: str) -> None:
    root = base_url.rstrip("/")
    session.get(f"{root}/", timeout=30)
    resp = session.post(
        f"{root}/api/v1/user/login",
        json={"username": username, "password": password},
        timeout=30,
    )
    resp.raise_for_status()
    _check_api_response(resp, "login")


def csrf_headers(session: requests.Session) -> dict[str, str]:
    token = (
        session.cookies.get("DTCsrfToken")
        or session.cookies.get("csrftoken")
        or session.cookies.get("CSRF-TOKEN")
    )
    headers = {"Referer": session.headers.get("Referer", "")}
    if token:
        headers["X-CSRFToken"] = token
        headers["csrf-token"] = token
        headers["CSRF-TOKEN"] = token
    return headers


def find_project_id(session: requests.Session, base_url: str, project_name: str) -> int:
    project_name = (project_name or "").strip()
    if not project_name:
        raise RuntimeError("project name is empty")
    root = base_url.rstrip("/")
    resp = session.get(
        f"{root}/api/v1/project/search",
        params={"name": project_name},
        timeout=30,
    )
    resp.raise_for_status()
    body = _check_api_response(resp, "project search")
    for item in body.get("data") or []:
        if item.get("name") == project_name:
            return int(item["id"])
    for item in body.get("data") or []:
        if project_name.lower() in str(item.get("name", "")).lower():
            return int(item["id"])
    names = [item.get("name") for item in (body.get("data") or [])[:20]]
    raise RuntimeError(f"project not found: {project_name!r} (search returned: {names})")


def list_project_versions(
    session: requests.Session, base_url: str, project_id: int
) -> list[dict]:
    root = base_url.rstrip("/")
    resp = session.get(f"{root}/api/v1/project/version/list/{project_id}", timeout=30)
    resp.raise_for_status()
    body = _check_api_response(resp, "version list")
    return list(body.get("data") or [])


def resolve_version_id(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_name: str,
) -> tuple[int, str]:
    """Return (version_id, resolved_version_name)."""
    version_name = (version_name or "").strip()
    versions = list_project_versions(session, base_url, project_id)
    if not versions:
        raise RuntimeError(f"project {project_id} has no versions")

    for item in versions:
        if item.get("version_name") == version_name:
            return int(item["version_id"]), str(item["version_name"])

    if version_name:
        run_matches = [v for v in versions if str(v.get("version_name", "")).startswith("run-")]
        if len(run_matches) == 1:
            item = run_matches[0]
            print(
                f"WARNING: exact version {version_name!r} not found; "
                f"using {item.get('version_name')!r}"
            )
            return int(item["version_id"]), str(item["version_name"])

    for item in versions:
        if int(item.get("current_version") or 0) == 1:
            print(
                f"WARNING: version {version_name!r} not found; "
                f"using current {item.get('version_name')!r}"
            )
            return int(item["version_id"]), str(item["version_name"])

    latest = max(versions, key=lambda v: int(v.get("version_id") or 0))
    print(
        f"WARNING: version {version_name!r} not found; "
        f"using latest {latest.get('version_name')!r}"
    )
    return int(latest["version_id"]), str(latest["version_name"])


def find_version_id(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_name: str,
) -> int:
    version_id, _ = resolve_version_id(session, base_url, project_id, version_name)
    return version_id


def list_project_agents(
    session: requests.Session,
    base_url: str,
    project_id: int,
    *,
    page_size: int = 50,
) -> list[dict]:
    """List agents bound to a project (v1 API, paginated)."""
    root = base_url.rstrip("/")
    agents: list[dict] = []
    page = 1
    while True:
        resp = session.get(
            f"{root}/api/v1/agents",
            params={"bind_project_id": project_id, "page": page, "pageSize": page_size},
            timeout=30,
        )
        resp.raise_for_status()
        body = _check_api_response(resp, "agent list")
        items = list(body.get("data") or [])
        if not items:
            break
        agents.extend(items)
        page_meta = body.get("page") or {}
        num_pages = int(page_meta.get("num_pages") or 0)
        if num_pages:
            if page >= num_pages:
                break
        elif len(items) < page_size:
            break
        page += 1
    return agents


def resolve_run_agent_ids(agents: list[dict], version_id: int) -> list[int]:
    """Agent ids for a CI run version; falls back to the highest agent id."""
    matched = [
        int(agent["id"])
        for agent in agents
        if int(agent.get("project_version") or 0) == int(version_id)
    ]
    if matched:
        return sorted(matched)
    if agents:
        latest = max(agents, key=lambda agent: int(agent.get("id") or 0))
        return [int(latest["id"])]
    return []


def normalize_vuln_record(item: dict) -> dict:
    """Unify v1/v2 vulnerability payloads for the scorecard."""
    uri = str(item.get("uri") or "")
    url = str(item.get("url") or "")
    if not uri and url:
        from urllib.parse import urlparse

        uri = urlparse(url).path or url
    vul_type = str(
        item.get("strategy__vul_name") or item.get("type") or item.get("vul_type") or ""
    )
    is_header = item.get("is_header_vul")
    if isinstance(is_header, str):
        is_header = is_header.lower() in ("1", "true", "yes")
    return {
        **item,
        "uri": uri,
        "url": url or uri,
        "type": vul_type,
        "strategy__vul_name": vul_type,
        "is_header_vul": bool(is_header),
        "http_method": str(item.get("http_method") or ""),
    }


def _fetch_vulnerabilities_v2(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_id: int,
    *,
    page_size: int = 500,
) -> tuple[list[dict], dict]:
    """Panel UI list API — no hard 50-item cap on page_size."""
    root = base_url.rstrip("/")
    headers = csrf_headers(session)
    vulns: list[dict] = []
    page = 1
    while True:
        payload = {
            "bind_project_id": project_id,
            "project_version_id": version_id,
            "page": page,
            "page_size": page_size,
            "order_type": 0,
            "order_type_desc": 0,
        }
        resp = session.post(
            f"{root}/api/v2/app_vul_list_content",
            json=payload,
            headers=headers,
            timeout=120,
        )
        resp.raise_for_status()
        body = _check_api_response(resp, "v2 vulnerability list")
        data = body.get("data") or {}
        if isinstance(data, list):
            items = data
        else:
            items = data.get("messages") or []
        if not items:
            break
        vulns.extend(normalize_vuln_record(item) for item in items)
        if len(items) < page_size:
            break
        page += 1
    meta = {
        "api": "v2/app_vul_list_content",
        "pages_fetched": page,
        "page_size": page_size,
    }
    return vulns, meta


def _fetch_vulnerabilities_v1(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_id: int,
    *,
    project_name: str = "",
    scope: str = "version",
    page_size: int = 50,
) -> tuple[list[dict], dict]:
    """Legacy GET /api/v1/vulns — server caps pageSize at 50, fetch every page."""
    root = base_url.rstrip("/")
    vulns: list[dict] = []
    page = 1
    total = 0
    num_pages = 0
    while True:
        params: dict[str, int | str] = {
            "page": page,
            "pageSize": page_size,
        }
        if scope == "version":
            params["project_id"] = project_id
            params["version_id"] = version_id
        else:
            params["project_name"] = (project_name or "").strip() or str(project_id)

        resp = session.get(
            f"{root}/api/v1/vulns",
            params=params,
            timeout=120,
        )
        resp.raise_for_status()
        body = _check_api_response(resp, "v1 vulnerability list")
        items = body.get("data") or []
        if not items:
            break
        vulns.extend(normalize_vuln_record(item) for item in items)
        page_meta = body.get("page") or {}
        total = int(page_meta.get("alltotal") or total or len(vulns))
        num_pages = int(page_meta.get("num_pages") or num_pages or 0)
        if num_pages:
            if page >= num_pages:
                break
        elif len(items) < page_size:
            break
        page += 1
    meta = {
        "api": "v1/vulns",
        "pages_fetched": page,
        "page_size": page_size,
        "alltotal": total,
        "num_pages": num_pages,
    }
    return vulns, meta


def fetch_panel_vulnerability_summary(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_id: int,
) -> dict:
    """Aggregate counts by IAST strategy type (same filters as the panel UI)."""
    root = base_url.rstrip("/")
    resp = session.post(
        f"{root}/api/v2/app_vul_summary",
        json={
            "bind_project_id": project_id,
            "project_version_id": version_id,
            "page": 1,
            "page_size": 1,
        },
        headers=csrf_headers(session),
        timeout=60,
    )
    resp.raise_for_status()
    body = _check_api_response(resp, "v2 vulnerability summary")
    data = body.get("data") or {}
    messages = data.get("messages") if isinstance(data, dict) else data
    if isinstance(messages, dict):
        return messages
    return {}


def fetch_all_vulnerabilities(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_id: int,
    *,
    project_name: str = "",
    scope: str = "version",
) -> tuple[list[dict], dict]:
    """
    Fetch every vulnerability for a project version.

    Prefer the v2 UI endpoint (large pages). Fall back to v1 with full pagination.
    """
    if scope == "version":
        try:
            vulns, meta = _fetch_vulnerabilities_v2(
                session, base_url, project_id, version_id
            )
            if vulns:
                meta["scope"] = scope
                return vulns, meta
        except requests.HTTPError as exc:
            body = ""
            if exc.response is not None:
                body = (exc.response.text or "")[:500]
            print(
                f"WARNING: v2 vulnerability fetch HTTP {getattr(exc.response, 'status_code', '?')} "
                f"({body!r}); falling back to v1"
            )
        except RuntimeError as exc:
            print(f"WARNING: v2 vulnerability fetch failed ({exc}); falling back to v1")

    vulns, meta = _fetch_vulnerabilities_v1(
        session,
        base_url,
        project_id,
        version_id,
        project_name=project_name,
        scope=scope,
    )
    meta["scope"] = scope
    return vulns, meta


def iter_vulnerabilities(
    session: requests.Session,
    base_url: str,
    project_id: int,
    version_id: int,
    *,
    project_name: str = "",
    scope: str = "project",
    page_size: int = 50,
) -> Iterator[dict]:
    """Backward-compatible iterator; loads all pages then yields."""
    if scope == "version":
        vulns, _ = fetch_all_vulnerabilities(
            session,
            base_url,
            project_id,
            version_id,
            project_name=project_name,
            scope=scope,
        )
    else:
        vulns, _ = _fetch_vulnerabilities_v1(
            session,
            base_url,
            project_id,
            version_id,
            project_name=project_name,
            scope=scope,
            page_size=page_size,
        )
    yield from vulns


def _flatten_config(config: dict) -> dict[str, str]:
    flat: dict[str, str] = {}
    project = config.get("project") or {}
    if project.get("name"):
        flat["project.name"] = str(project["name"])
    if project.get("version"):
        flat["project.version"] = str(project["version"])
    return flat


def _resolve_agent_artifact(agent_artifact: str) -> Path | None:
    path = Path(agent_artifact)
    if path.is_file():
        return path
    if path.is_dir():
        candidates = sorted(path.glob("*.whl")) + sorted(path.glob("*.tar.gz"))
        if candidates:
            return candidates[-1]
    return None


def read_agent_properties(agent_artifact: str) -> dict[str, str]:
    """Read project metadata from a Java agent.jar or Python agent wheel/sdist."""
    path = _resolve_agent_artifact(agent_artifact)
    if path is None:
        return {}

    if path.suffix == ".whl":
        try:
            with zipfile.ZipFile(path) as zf:
                for name in zf.namelist():
                    if name.endswith("immunity_python_agent/config.json"):
                        config = json.loads(zf.read(name).decode("utf-8"))
                        return _flatten_config(config)
        except (OSError, json.JSONDecodeError, zipfile.BadZipFile):
            return {}

    if path.suffix == ".gz" or path.name.endswith(".tar.gz"):
        try:
            import tarfile

            with tarfile.open(path, "r:gz") as tar:
                for item in tar.getmembers():
                    if item.name.endswith("immunity_python_agent/config.json"):
                        raw = tar.extractfile(item)
                        if raw is None:
                            return {}
                        config = json.loads(raw.read().decode("utf-8"))
                        return _flatten_config(config)
        except (OSError, json.JSONDecodeError, tarfile.TarError):
            return {}

    if path.suffix == ".jar":
        props: dict[str, str] = {}
        try:
            with zipfile.ZipFile(path) as zf:
                raw = zf.read("iast.properties").decode("utf-8", errors="replace")
        except (KeyError, OSError):
            return props
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
        return props

    return {}

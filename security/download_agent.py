#!/usr/bin/env python3
"""Download Immunity Python agent and validate the artifact (wheel or sdist tar.gz)."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

import ssl


def _build_download_url(
    server: str,
    *,
    project_name: str,
    project_version: str,
    template_id: str,
    py_tag: str,
    platform: str,
) -> str:
    params = urlencode(
        {
            "url": server,
            "language": "python",
            "projectName": project_name,
            "projectVersion": project_version,
            "template_id": template_id,
            "py": py_tag,
            "platform": platform,
        }
    )
    return f"{server.rstrip('/')}/api/v1/agent/download?{params}"


def _filename_from_disposition(header: str | None) -> str | None:
    if not header:
        return None
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', header, re.I)
    return match.group(1).strip() if match else None


def _canonical_wheel_filename(path: Path) -> str:
    """Build a PEP 427 wheel filename from archive metadata (pip rejects agent.whl)."""
    with zipfile.ZipFile(path) as zf:
        wheel_paths = [name for name in zf.namelist() if name.endswith(".dist-info/WHEEL")]
        if not wheel_paths:
            raise RuntimeError(f"No .dist-info/WHEEL inside archive: {path}")
        dist_info_dir = wheel_paths[0].rsplit("/", 1)[0]
        if not dist_info_dir.endswith(".dist-info"):
            raise RuntimeError(f"Unexpected dist-info path: {dist_info_dir}")
        project_version = dist_info_dir[: -len(".dist-info")]
        wheel_meta = zf.read(wheel_paths[0]).decode("utf-8", errors="replace")
        tags = [
            line.split("Tag:", 1)[1].strip()
            for line in wheel_meta.splitlines()
            if line.startswith("Tag:")
        ]
        if not tags:
            raise RuntimeError(f"No Tag entries in WHEEL metadata: {path}")
        return f"{project_version}-{tags[0]}.whl"


def _is_valid_wheel_filename(name: str) -> bool:
    return bool(re.match(r"^[^\s/]+-\d[^\s/]*-[^-]+-[^-]+-[^-]+\.whl$", name))


def _guess_kind(path: Path) -> str:
    data = path.read_bytes()[:8]
    if data.startswith(b"PK"):
        return "wheel"
    if data.startswith(b"\x1f\x8b"):
        return "sdist"
    preview = path.read_bytes()[:400].decode("utf-8", errors="replace").strip()
    if preview.startswith("{") or preview.startswith("<"):
        raise RuntimeError(f"Server returned an error page, not an agent:\n{preview[:300]}")
    raise RuntimeError(f"Unknown agent artifact (magic={data!r}, size={path.stat().st_size})")


def _read_config_from_wheel(path: Path) -> dict:
    with zipfile.ZipFile(path) as zf:
        cfg_names = [n for n in zf.namelist() if n.endswith("immunity_python_agent/config.json")]
        if not cfg_names:
            cfg_names = [n for n in zf.namelist() if n.endswith("config.json")]
        if not cfg_names:
            raise RuntimeError(f"No config.json inside wheel: {path}")
        return json.loads(zf.read(cfg_names[0]).decode("utf-8"))


def _read_config_from_sdist(path: Path) -> dict:
    with tarfile.open(path, "r:gz") as tar:
        member = None
        for item in tar.getmembers():
            if item.name.endswith("immunity_python_agent/config.json"):
                member = item
                break
        if member is None:
            raise RuntimeError(f"No config.json inside sdist: {path}")
        raw = tar.extractfile(member)
        if raw is None:
            raise RuntimeError(f"Could not read config.json from sdist: {path}")
        return json.loads(raw.read().decode("utf-8"))


def download_agent(
    *,
    server: str,
    token: str,
    out_dir: Path,
    project_name: str,
    project_version: str,
    template_id: str,
    py_tag: str,
    platform: str,
    verify_ssl: bool,
) -> tuple[Path, str, dict]:
    out_dir.mkdir(parents=True, exist_ok=True)
    url = _build_download_url(
        server,
        project_name=project_name,
        project_version=project_version,
        template_id=template_id,
        py_tag=py_tag,
        platform=platform,
    )
    request = Request(url, headers={"Authorization": f"Token {token}"})
    context = None if verify_ssl else ssl._create_unverified_context()

    with urlopen(request, context=context, timeout=120) as response:
        disposition = response.headers.get("Content-Disposition")
        suggested = _filename_from_disposition(disposition)
        tmp_path = out_dir / "agent.download"
        tmp_path.write_bytes(response.read())

    kind = _guess_kind(tmp_path)
    if kind == "wheel":
        final_name = _canonical_wheel_filename(tmp_path)
    elif suggested and suggested.endswith(".tar.gz"):
        final_name = suggested
    else:
        final_name = "immunity_agent_python.tar.gz"

    if kind == "wheel" and not _is_valid_wheel_filename(final_name):
        raise RuntimeError(f"Wheel filename is not PEP 427 compatible: {final_name}")

    final_path = out_dir / final_name
    if final_path.exists():
        final_path.unlink()
    tmp_path.replace(final_path)

    if kind == "wheel":
        zipfile.ZipFile(final_path)  # validate
        config = _read_config_from_wheel(final_path)
    else:
        tarfile.open(final_path, "r:gz")  # validate
        config = _read_config_from_sdist(final_path)

    return final_path, kind, config


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", default=os.environ.get("IAST_SERVER_URL", ""))
    parser.add_argument("--token", default=os.environ.get("IAST_TOKEN", ""))
    parser.add_argument("--out-dir", default="iast-tool")
    parser.add_argument("--project-name", default=os.environ.get("IAST_PROJECT_NAME", "benchmarkpython"))
    parser.add_argument("--project-version", default=os.environ.get("PROJECT_VERSION", ""))
    parser.add_argument("--template-id", default=os.environ.get("IAST_TEMPLATE_ID", "2"))
    parser.add_argument("--py-tag", default=os.environ.get("IAST_PY_TAG", "cp312"))
    parser.add_argument("--platform", default=os.environ.get("IAST_PLATFORM", "manylinux_2_28_x86_64"))
    parser.add_argument("--github-env", default="", help="Write AGENT_ARTIFACT=... to this file")
    parser.add_argument("--print-path", action="store_true", help="Print artifact path to stdout")
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        default=os.environ.get("IAST_VERIFY_SSL", "false").lower() in ("1", "true", "yes"),
    )
    args = parser.parse_args()

    if not args.server or not args.token:
        print("Set IAST_SERVER_URL and IAST_TOKEN", file=sys.stderr)
        return 2
    if not args.project_version:
        print("Set PROJECT_VERSION", file=sys.stderr)
        return 2

    artifact, kind, config = download_agent(
        server=args.server,
        token=args.token,
        out_dir=Path(args.out_dir),
        project_name=args.project_name,
        project_version=args.project_version,
        template_id=str(args.template_id),
        py_tag=args.py_tag,
        platform=args.platform,
        verify_ssl=args.verify_ssl,
    )

    if args.github_env:
        with open(args.github_env, "a", encoding="utf-8") as fh:
            fh.write(f"AGENT_ARTIFACT={artifact.resolve()}\n")

    if args.print_path:
        print(artifact.resolve())
    else:
        print(
            f"Downloaded {kind} artifact: {artifact.resolve()} "
            f"({artifact.stat().st_size} bytes)"
        )
        print(json.dumps(config, indent=2, ensure_ascii=False))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

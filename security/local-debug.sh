#!/usr/bin/env bash
# Local IAST + OWASP crawler loop (no CI). Reads secrets from security/.env.local
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENV_FILE="${ROOT}/security/.env.local"
AGENT_DIR="${ROOT}/iast-tool"
SERVER_LOG="${ROOT}/benchmark-server.log"
SERVER_PID="${ROOT}/benchmark-server.pid"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a && source "$ENV_FILE" && set +a
fi

: "${IAST_SERVER_URL:?Set IAST_SERVER_URL in security/.env.local}"
: "${IAST_TOKEN:?Set IAST_TOKEN in security/.env.local}"
: "${PANEL_URL:?Set PANEL_URL in security/.env.local}"
: "${PANEL_USER:?Set PANEL_USER in security/.env.local}"
: "${PANEL_PASS:?Set PANEL_PASS in security/.env.local}"

IAST_PROJECT_BASE="${IAST_PROJECT_NAME:-benchmarkpython}"
IAST_TEMPLATE_ID="${IAST_TEMPLATE_ID:-2}"
PY_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
IAST_PROJECT_NAME="${IAST_PROJECT_BASE}-py${PY_VERSION}"
IAST_PY_TAG="${IAST_PY_TAG:-cp${PY_VERSION//./}}"
IAST_PLATFORM="${IAST_PLATFORM:-manylinux_2_28_x86_64}"
BENCHMARK_BASE_URL="${BENCHMARK_BASE_URL:-https://127.0.0.1:8443/benchmark}"
VERSION="local-$(date +%s)"
SERVER="${IAST_SERVER_URL%/}"

cleanup() {
  if [[ -f "$SERVER_PID" ]]; then
    kill "$(cat "$SERVER_PID")" 2>/dev/null || true
  fi
  pkill -f 'flask --app app.py' 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Download Python agent (${SERVER}, project=${IAST_PROJECT_NAME}, version=${VERSION})"
export PROJECT_VERSION="${VERSION}"
AGENT_ARTIFACT="$(python3 "${ROOT}/security/download_agent.py" \
  --server "${SERVER}" \
  --token "${IAST_TOKEN}" \
  --out-dir "${AGENT_DIR}" \
  --project-name "${IAST_PROJECT_NAME}" \
  --project-version "${VERSION}" \
  --template-id "${IAST_TEMPLATE_ID}" \
  --py-tag "${IAST_PY_TAG}" \
  --platform "${IAST_PLATFORM}" \
  --print-path)"
test -n "${AGENT_ARTIFACT}"
test -s "${AGENT_ARTIFACT}"

echo "==> Prepare venv and install agent"
cd "${ROOT}"
if [[ ! -d venv ]]; then
  python3 -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install -q -r requirements.txt
pip install -q -r security/requirements.txt
pip install -q "${AGENT_ARTIFACT}"

echo "==> Start Benchmark with Immunity Python agent (non-invasive)"
export IMMUNITY_CTL_SKIP_UPDATE=1
nohup immunity-agent run flask --app app.py run --port 8443 --cert=adhoc --host=127.0.0.1 \
  > "${SERVER_LOG}" 2>&1 &
echo $! > "${SERVER_PID}"

echo "==> Wait for Benchmark"
for attempt in $(seq 1 90); do
  if ! kill -0 "$(cat "$SERVER_PID")" 2>/dev/null; then
    echo "Flask process exited before becoming ready" >&2
    tail -n 200 "$SERVER_LOG" || true
    exit 1
  fi
  if curl -kfsS "https://127.0.0.1:8443/redirected" >/dev/null 2>&1; then
    echo "Benchmark up after ${attempt} attempt(s)"
    break
  fi
  echo "  waiting... (${attempt}/90)"
  sleep 10
done
curl -kfsS "https://127.0.0.1:8443/redirected" >/dev/null

echo "==> Agent started; wait 30s for panel registration"
sleep 30
grep -i 'immunity-loader\|automatic flask middleware\|agent register' "${SERVER_LOG}" | tail -20 || true

echo "==> Crawl"
python3 security/run_crawler.py --base-url "https://127.0.0.1:8443"

echo "==> Wait for method pool upload (4 min)"
sleep 240

echo "==> Score IAST vs OWASP Benchmark"
export PANEL_URL="${PANEL_URL:-${IAST_SERVER_URL}}"
export PROJECT_VERSION="${VERSION}"
python3 "${ROOT}/security/score_iast_benchmark.py" \
  --agent-artifact "${AGENT_ARTIFACT}" \
  --vuln-scope version \
  --output-json "${ROOT}/scorecard-iast.json" \
  --output-md "${ROOT}/scorecard-iast.md"

echo "Done. Scorecard: ${ROOT}/scorecard-iast.md"

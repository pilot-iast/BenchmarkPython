#!/bin/sh
# Start OWASP Benchmark for Python with Immunity IAST agent (iast-tool/*.whl or *.tar.gz).
# Download agent first — see security/local-debug.sh or CI workflow.

set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AGENT="$(find "${ROOT}/iast-tool" -maxdepth 1 \( -name '*.whl' -o -name '*.tar.gz' \) | head -n 1)"

if [ -z "$AGENT" ] || [ ! -s "$AGENT" ]; then
  echo "Missing agent artifact in ${ROOT}/iast-tool/"
  echo "Run security/local-debug.sh or download agent from management-server first"
  exit 1
fi

cd "$ROOT"

if [ ! -d venv ]; then
  python3 -m venv venv
fi

# shellcheck disable=SC1091
. venv/bin/activate
pip install -q -r requirements.txt
pip install -q "${AGENT}"

export IMMUNITY_IAST=1
echo "Starting Benchmark for Python with Immunity IAST agent: ${AGENT}"
echo "When Flask is up, run ./runCrawler.sh in another terminal."
echo "Press Ctrl+C here to stop the server."
exec flask --app app.py run --port 8443 --cert=adhoc --host=127.0.0.1

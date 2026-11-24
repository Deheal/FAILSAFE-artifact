#!/usr/bin/env bash
set -euo pipefail
C=authentik-run_server_1
W=authentik-run_worker_1
F=/authentik/stages/authenticator_validate/challenge.py
LOCAL="${FS2_WORKDIR:-$HOME/fs2}"; mkdir -p "$LOCAL"
PROJ="$(cd "$(dirname "$0")/../.." && pwd)"

gen_patch() {
  docker cp "$C:$F" "$LOCAL/challenge.live.py"
  "${PYTHON:-python3}" - <<PY
import sys; sys.path.insert(0, "$PROJ/scripts/defects")
from authentik_fs2 import patch_text
src = open("$LOCAL/challenge.live.py").read()
open("$LOCAL/challenge.fs2.py", "w").write(patch_text(src))
import ast; ast.parse(open("$LOCAL/challenge.fs2.py").read())
print("patched + syntax ok")
PY
}

case "${1:-}" in
  apply)
    docker cp "$C:$F" "$LOCAL/challenge.backup.py"
    gen_patch
    docker cp "$LOCAL/challenge.fs2.py" "$C:$F"
    docker cp "$LOCAL/challenge.fs2.py" "$W:$F" 2>/dev/null || true
    docker restart "$C" "$W" >/dev/null
    echo "FS-2 applied; waiting for health..."
    ;;
  restore)
    docker cp "$LOCAL/challenge.backup.py" "$C:$F"
    docker cp "$LOCAL/challenge.backup.py" "$W:$F" 2>/dev/null || true
    docker restart "$C" "$W" >/dev/null
    echo "restored; waiting for health..."
    ;;
  *) echo "usage: $0 apply|restore"; exit 1;;
esac

for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:9400/-/health/ready/ || true)
  [ "$code" = "204" -o "$code" = "200" ] && { echo "ready ($code)"; exit 0; }
  sleep 2
done
echo "health timeout"; exit 1

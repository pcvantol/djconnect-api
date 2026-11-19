#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
lab=$(mktemp -d "${TMPDIR:-/tmp}/watch-dispatch-fence.XXXXXXXX")
pid=
port=$(node -e 'const s=require("node:net").createServer();s.listen(0,"127.0.0.1",()=>{console.log(s.address().port);s.close()})')

stop() {
  if [[ -n "$pid" ]]; then
    kill -INT "$pid" 2>/dev/null || true
    wait "$pid" || true
    pid=
  fi
}
cleanup() {
  stop
  rm -rf -- "$lab"
}
trap cleanup EXIT

boot() {
  "$root/node_modules/.bin/wrangler" dev --local --ip 127.0.0.1 --port "$port" \
    --config "$root/qualification/watch-moment/dispatch-fence-wrangler.json" \
    --persist-to "$lab/state" > "$lab/worker.log" 2>&1 &
  pid=$!
  for ((i=0; i<80; i++)); do
    if call 'state?installation=probe' >/dev/null 2>&1; then return; fi
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.25
  done
  cat "$lab/worker.log"
  return 1
}
call() {
  curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:$port/$1"
}
start() {
  call "start?installation=clock&$1" | jq -e --argjson expected "$2" '.admitted == $expected' >/dev/null
}
assert_retired() {
  call 'start?installation=retired' | jq -e '.admitted == false' >/dev/null
  call 'state?installation=retired' | jq -e '.revoked == 1 and .starts == 0' >/dev/null
}

boot
call 'revoke?installation=retired' | jq -e '.revoked == true' >/dev/null
assert_retired
start 'lease=old&now=1000&expires=1500' true
start 'lease=old&now=1499&expires=1500' false
start 'lease=old&now=1500&expires=1500' false
start 'lease=new&now=1500&expires=1700' true
start 'lease=old&now=1499&expires=1500' false

stop
if call 'state?installation=probe' >/dev/null 2>&1; then
  echo 'The first Workerd listener is still active.' >&2
  exit 1
fi
boot
assert_retired
start 'lease=old&now=1499&expires=1500' false
start 'lease=new&now=1501&expires=1700' false
call 'state?installation=clock' | jq -e '.starts == 2' >/dev/null
echo 'PASS Watch retirement, exact replay, expiration and clock floor survived Workerd restart'

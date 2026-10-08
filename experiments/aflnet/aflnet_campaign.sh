#!/usr/bin/env bash
# AFLNet baseline campaign against a live OAuth target (CS revision).
# One-shot relay + dumb mode (SPIKE_NOTES.md working formula; JVM/Go targets
# cannot provide AFL forkserver coverage, so -n is the only operable mode).
# Coverage is measured at the TARGET by coverage_sampler.py (separate proc).
#
# FAIRNESS FIX: SEEDS is now MANDATORY and must point at per-target seeds
# built by build_seeds.py (v1 accidentally fuzzed all lanes with CXF seeds).
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../../.." && pwd)"
AFLNET="${AFLNET:-$HOME/tools/aflnet}"

TARGET="${TARGET:-cxf_oauth}"
UP_HOST="${UP_HOST:-127.0.0.1}"
UP_PORT="${UP_PORT:-8081}"
PORT="${PORT:-26000}"
DURATION_H="${DURATION_H:-6}"
OUT="${OUT:?OUT must be set}"
SEEDS="${SEEDS:?SEEDS must be set to a per-target seeds dir (see build_seeds.py)}"

export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export LD_LIBRARY_PATH="$HOME/tools/sysroot/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

mkdir -p "$OUT"
cd "$REPO"

DH="${DURATION_H%.*}"
deadline=$(( $(date +%s) + DH*3600 ))
pass=0
IN_DIR="$SEEDS"
while [ "$(date +%s)" -lt "$deadline" ]; do
  pass=$((pass+1))
  echo "[aflnet-campaign] pass $pass start in=$IN_DIR $(date -Is)" >> "$OUT/campaign.log"
  timeout -k 30 $(( DH*3600 / 8 + 3600 )) \
    "$AFLNET/afl-fuzz" -i "$IN_DIR" -o "$OUT" -n -E \
    -N "tcp://127.0.0.1/$PORT" -P HTTP -m none -t 5000 \
    -- python3 "$HERE/relay_oneshot.py" "${UP_HOST}:${UP_PORT}" "$PORT" \
    >> "$OUT/campaign.log" 2>&1
  echo "[aflnet-campaign] pass $pass end rc=$? $(date -Is)" >> "$OUT/campaign.log"
  IN_DIR="-"   # AFL resume semantics: -i- resumes the existing out dir
  sleep 2
done

grep -E "execs_done|execs_per_sec|corpus_count" "$OUT/fuzzer_stats" > "$OUT/final_stats.txt" 2>/dev/null || true
echo "done: $(date -Is)" >> "$OUT/campaign.log"

#!/bin/bash
# Batch post-hoc corpus replay over all DONE matrix campaigns (week-2 phase).
# Sequential — one pristine replay instance at a time (RAM-bounded).
# Skips campaigns already having replay_coverage.json.
# boofuzz_keycloak_* corpora contain the deterministic ~2h kill-shot input
# (verified twice); replaying them would kill the pristine KC instance
# mid-corpus. They are EXCLUDED here pending a resurrection-aware replay.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS="$HERE/results"
cd "$HERE"
for d in "$RESULTS"/matrix/oauthfuzz_* \
         "$RESULTS"/matrix/aflnet_* \
         "$RESULTS"/matrix/boofuzz_cxf_oauth_* \
         "$RESULTS"/matrix/boofuzz_authelia_*; do
  name="$(basename "$d")"
  case "$name" in
    boofuzz_keycloak_*) echo "[replay-all] SKIP $name (kill-shot, deferred)"; continue;;
  esac
  if [ ! -f "$d/DONE" ]; then
    echo "[replay-all] SKIP $name (no DONE)"; continue
  fi
  if [ -f "$d/replay_coverage.json" ]; then
    echo "[replay-all] done already: $name"; continue
  fi
  echo "[replay-all] replaying $name ..."
  python3 replay_corpus.py --campaign "$d" 2>&1 | tail -2
done
echo "[replay-all] BATCH COMPLETE"

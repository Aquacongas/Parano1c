#!/usr/bin/env bash
# test_partition.sh — Chain fork + reconnect test
# =================================================
#
# Core invariant: any node (mining or not) that connects to a peer
# with more chainwork MUST converge to that peer's chain.
# In Paranoid, snapshot sync is O(1) — convergence must happen in seconds.
#
# TWO SCENARIOS:
#
#  S1: C has more work, A syncs to C  (C reconnects without --mine)
#  S2: A has more work, C syncs to A  (C reconnects WITH --mine)
#      This specifically tests that mining during reconnect doesn't block sync.
#
# Two nodes only (A and C). No three-way race conditions.
# B is not used — two nodes is all we need to test fork resolution.
#
# Usage:
#   cd /path/to/paranoid && bash tests/stress/test_partition.sh

set -uo pipefail
BIN="./target/release/paranoid"
RPC_A="http://127.0.0.1:18041"
RPC_C="http://127.0.0.1:18043"
PASS=0; FAIL=0
ALL_PIDS=()

# ---------------------------------------------------------------------------
rpc()      { curl -s -X POST "$1" -H 'Content-Type: application/json' \
               -d "{\"jsonrpc\":\"2.0\",\"method\":\"paranoid_$2\",\"params\":${3:-[]},\"id\":1}"; }
height()   { rpc "$1" getChainInfo | python3 -c \
               "import sys,json; print(json.load(sys.stdin).get('result',{}).get('height',-1))" 2>/dev/null || echo -1; }
best_hash(){ rpc "$1" getChainInfo | python3 -c \
               "import sys,json; print(json.load(sys.stdin).get('result',{}).get('best_hash',''))" 2>/dev/null || echo ''; }
hash_at()  { rpc "$1" getBlockHash "[${2}]" | python3 -c \
               "import sys,json; print(json.load(sys.stdin).get('result','') or '')" 2>/dev/null || echo ''; }
# count_log: awk always exits 0; avoid grep -c which exits 1 on no match.
# Use two separate awk calls for OR-patterns (\| is not portable in awk regex).
count_log()  { awk "/$1/{c++} END{print c+0}" "$2" 2>/dev/null; }
count_log2() { echo $(( $(awk "/$1/{c++} END{print c+0}" "$3" 2>/dev/null) + $(awk "/$2/{c++} END{print c+0}" "$3" 2>/dev/null) )); }

ok()   { echo "  PASS ✓ $*"; PASS=$((PASS+1)); }
fail() { echo "  FAIL ✗ $*"; FAIL=$((FAIL+1)); }

wait_alive() {
    for i in $(seq 1 30); do
        h=$(height "$1"); [ "$h" -ge 0 ] 2>/dev/null && return 0; sleep 0.5
    done; echo "  WARN: $2 RPC not alive after 15s"; return 1
}

wait_height() {
    echo -n "  $3 → h>=$2 ."
    for i in $(seq 1 120); do
        h=$(height "$1"); [ "$h" -ge "$2" ] 2>/dev/null && echo " h=$h" && return 0
        echo -n "."; sleep 1
    done; echo " TIMEOUT"; return 1
}

# Wait until two nodes share the same hash (compare at the lower height to
# avoid timing skew — one node may have found an extra block since last check).
wait_converge() {
    local url1=$1 url2=$2 label=$3 max=${4:-60}
    echo -n "  $label converge ."
    for i in $(seq 1 "$max"); do
        h1=$(height "$url1"); h2=$(height "$url2")
        if [ "$h1" -ge 2 ] 2>/dev/null && [ "$h2" -ge 2 ] 2>/dev/null; then
            common=$(( h1 < h2 ? h1 : h2 ))
            ha=$(hash_at "$url1" "$common"); hb=$(hash_at "$url2" "$common")
            if [ -n "$ha" ] && [ "$ha" = "$hb" ]; then
                echo " ✓ h=$common in ${i}s  ${ha:0:16}..."
                return 0
            fi
        fi
        echo -n "."; sleep 1
    done; echo " TIMEOUT (${max}s)"; return 1
}

check_no_panic() {
    grep -q "panicked\|PANIC\|stack overflow" "$2" 2>/dev/null \
        && { fail "Node $1 panicked"; tail -3 "$2"; } \
        || ok "Node $1 no panics"
}

cleanup() {
    echo ""; echo "--- Cleanup ---"
    for pid in "${ALL_PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1; rm -rf /tmp/ptest-{s1,s2}-{A,C}
}
trap cleanup EXIT

[ -f "$BIN" ] || { echo "ERROR: $BIN not found — cargo build --release"; exit 1; }

echo "======================================================================"
echo " Paranoid Fork/Reconnect Test  (~5s blocks at genesis difficulty)"
echo " Core invariant: any node MUST converge to the heavier chain fast."
echo "======================================================================"

# =============================================================================
# SCENARIO 1: C has more work → A syncs to C's chain
# =============================================================================
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo " S1: C gets head start → C has more work → A must sync to C"
echo "══════════════════════════════════════════════════════════════════════"

S1A=/tmp/ptest-s1-A; S1C=/tmp/ptest-s1-C
L1A=/tmp/ptest-s1-A.log; L1C=/tmp/ptest-s1-C.log
rm -rf "$S1A" "$S1C"; mkdir -p "$S1A" "$S1C"

# Start A with genesis, mine 6 blocks to establish chain
"$BIN" --data-dir "$S1A" --p2p-listen 0.0.0.0:19041 --rpc-listen 127.0.0.1:18041 \
    --mine --testnet --genesis >"$L1A" 2>&1 &
P1A=$!; ALL_PIDS+=($P1A); echo "  A pid=$P1A (genesis)"
wait_alive "$RPC_A" A
wait_height "$RPC_A" 6 A

# Start C, let it sync to A then stop both — so they share the same fork point
"$BIN" --data-dir "$S1C" --p2p-listen 0.0.0.0:19043 --rpc-listen 127.0.0.1:18043 \
    --mine --testnet --seed 127.0.0.1:19041 --testnet >"$L1C" 2>&1 &
P1C=$!; ALL_PIDS+=($P1C); echo "  C pid=$P1C (syncs to A)"
wait_alive "$RPC_C" C
wait_height "$RPC_C" 6 C
# Give them a moment to agree
sleep 3
H1_FORK=$(height "$RPC_A")  # common fork point height

# Stop BOTH — C will get a clean head start
kill "$P1A" 2>/dev/null; wait "$P1A" 2>/dev/null || true
kill "$P1C" 2>/dev/null; wait "$P1C" 2>/dev/null || true
sleep 1
echo "  Fork point: h=$H1_FORK. Both stopped."

# C mines ALONE (+6 blocks) — A is frozen
"$BIN" --data-dir "$S1C" --p2p-listen 0.0.0.0:19043 --rpc-listen 127.0.0.1:18043 \
    --mine --testnet >"$L1C" 2>&1 &
P1C=$!; ALL_PIDS+=($P1C)
wait_alive "$RPC_C" C

C_TARGET=$((H1_FORK + 6))
echo "  C mines alone to h>=$C_TARGET (+6 head start, A frozen)"
wait_height "$RPC_C" "$C_TARGET" "C"
H1_C=$(height "$RPC_C")
echo "  C at h=$H1_C. Stopping C."
kill "$P1C" 2>/dev/null; wait "$P1C" 2>/dev/null || true; sleep 1

# A mines 3 blocks alone on its fork, then STOPS so we know its exact height.
# (A keeps mining past wait_height if we don't stop it — must kill before check.)
"$BIN" --data-dir "$S1A" --p2p-listen 0.0.0.0:19041 --rpc-listen 127.0.0.1:18041 \
    --mine --testnet >"$L1A" 2>&1 &
P1A=$!; ALL_PIDS+=($P1A)
wait_alive "$RPC_A" A

A_TARGET=$((H1_FORK + 3))
wait_height "$RPC_A" "$A_TARGET" "A"
# Read height BEFORE kill (RPC goes down after kill).
# We stop it quickly to minimise extra blocks after the read.
H1_A=$(height "$RPC_A")
kill "$P1A" 2>/dev/null; wait "$P1A" 2>/dev/null || true; sleep 1

echo "  Fork snapshot: A h=$H1_A (stopped)  C h=$H1_C (stopped)"
[ "$H1_C" -gt "$H1_A" ] 2>/dev/null \
    && ok "S1 C taller than A by $(( H1_C - H1_A )) blocks" \
    || fail "S1 C not taller (h_C=$H1_C h_A=$H1_A)"

# Reconnect: restart A (will mine from its fork), then connect C to A.
# C detects A has less work → A detects C has more work → A adopts C's chain.
T_CONN=$(date +%s)
echo ""
echo "  Restarting A, reconnecting C (no --mine) → expect A to adopt C's chain..."
"$BIN" --data-dir "$S1A" --p2p-listen 0.0.0.0:19041 --rpc-listen 127.0.0.1:18041 \
    --mine --testnet >"$L1A" 2>&1 &
P1A=$!; ALL_PIDS+=($P1A)
wait_alive "$RPC_A" A

"$BIN" --data-dir "$S1C" --p2p-listen 0.0.0.0:19043 --rpc-listen 127.0.0.1:18043 \
    --seed 127.0.0.1:19041 --testnet >"$L1C" 2>&1 &
P1C=$!; ALL_PIDS+=($P1C)
wait_alive "$RPC_C" C

if wait_converge "$RPC_A" "$RPC_C" "S1 A+C" 60; then
    SECS=$(( $(date +%s) - T_CONN ))
    ok "S1 A+C converged in ${SECS}s"
    [ "$SECS" -le 30 ] && ok "S1 fast convergence (≤30s, got ${SECS}s)" \
                       || fail "S1 slow convergence (>30s, got ${SECS}s)"
    # Verify A reorged (adopted C's chain which is taller)
    FA=$(height "$RPC_A"); FC=$(height "$RPC_C")
    [ "$FA" -ge "$H1_C" ] 2>/dev/null \
        && ok "S1 A adopted C's chain (A h=$FA ≥ C-before-reconnect h=$H1_C)" \
        || fail "S1 A not at C's level (A h=$FA C h=$H1_C)"
    R=$(count_log2 "reorg" "snapshot" "$L1A")
    echo "  Reorg/snapshot log entries in A: $R"
    [ "$R" -gt 0 ] 2>/dev/null && ok "S1 A shows chain-switch in logs" \
                                || fail "S1 no chain-switch in A logs"
else
    fail "S1 no convergence in 60s"
    echo "  A=$(best_hash "$RPC_A" | cut -c1-20)"
    echo "  C=$(best_hash "$RPC_C" | cut -c1-20)"
fi

check_no_panic "S1-A" "$L1A"
check_no_panic "S1-C" "$L1C"
kill "$P1A" "$P1C" 2>/dev/null || true
wait "$P1A" "$P1C" 2>/dev/null || true
sleep 2

# =============================================================================
# SCENARIO 2: A has more work → C (WITH --mine) syncs to A
# =============================================================================
echo ""
echo "══════════════════════════════════════════════════════════════════════"
echo " S2: A has more work → C (reconnects WITH --mine) must sync to A"
echo "  Tests: sync_ready arm cancels miner PoW, deep-fork → snapshot"
echo "══════════════════════════════════════════════════════════════════════"

S2A=/tmp/ptest-s2-A; S2C=/tmp/ptest-s2-C
L2A=/tmp/ptest-s2-A.log; L2C=/tmp/ptest-s2-C.log
rm -rf "$S2A" "$S2C"; mkdir -p "$S2A" "$S2C"

"$BIN" --data-dir "$S2A" --p2p-listen 0.0.0.0:19041 --rpc-listen 127.0.0.1:18041 \
    --mine --testnet --genesis >"$L2A" 2>&1 &
P2A=$!; ALL_PIDS+=($P2A); echo "  A pid=$P2A (genesis)"
wait_alive "$RPC_A" A
wait_height "$RPC_A" 6 A

"$BIN" --data-dir "$S2C" --p2p-listen 0.0.0.0:19043 --rpc-listen 127.0.0.1:18043 \
    --mine --testnet --seed 127.0.0.1:19041 --testnet >"$L2C" 2>&1 &
P2C=$!; ALL_PIDS+=($P2C); echo "  C pid=$P2C (syncs to A)"
wait_alive "$RPC_C" C
wait_height "$RPC_C" 6 C
sleep 3
H2_FORK=$(height "$RPC_A")

# Stop BOTH — A will get the head start this time
kill "$P2A" 2>/dev/null; wait "$P2A" 2>/dev/null || true
kill "$P2C" 2>/dev/null; wait "$P2C" 2>/dev/null || true
sleep 1
echo "  Fork point: h=$H2_FORK. Both stopped."

# A mines ALONE (+6) — C is frozen
"$BIN" --data-dir "$S2A" --p2p-listen 0.0.0.0:19041 --rpc-listen 127.0.0.1:18041 \
    --mine --testnet >"$L2A" 2>&1 &
P2A=$!; ALL_PIDS+=($P2A)
wait_alive "$RPC_A" A

# A gets a +12 head start (vs C's +2).
# Read height BEFORE kill so RPC is still alive.
A_TARGET2=$((H2_FORK + 12))
echo "  A mines alone to h>=$A_TARGET2 (+12 head start, C frozen)"
wait_height "$RPC_A" "$A_TARGET2" "A"
H2_A=$(height "$RPC_A")    # read before kill — RPC still up
kill "$P2A" 2>/dev/null; wait "$P2A" 2>/dev/null || true; sleep 1
echo "  A at h=$H2_A. Stopped."

# C mines alone (+2) — A is stopped
"$BIN" --data-dir "$S2C" --p2p-listen 0.0.0.0:19043 --rpc-listen 127.0.0.1:18043 \
    --mine --testnet >"$L2C" 2>&1 &
P2C=$!; ALL_PIDS+=("$P2C")
wait_alive "$RPC_C" C

C_TARGET2=$((H2_FORK + 2))
wait_height "$RPC_C" "$C_TARGET2" "C"
H2_C=$(height "$RPC_C")    # read before kill
kill "$P2C" 2>/dev/null; wait "$P2C" 2>/dev/null || true; sleep 1
echo "  C at h=$H2_C. Stopped."

echo "  Before reconnect: A h=$H2_A (fork+12)  C h=$H2_C (fork+2)"
[ "$H2_A" -gt "$H2_C" ] 2>/dev/null \
    && ok "S2 A taller than C by $(( H2_A - H2_C )) blocks" \
    || fail "S2 A not taller (h_A=$H2_A h_C=$H2_C)"

# Restart BOTH — C reconnects WITH --mine
# C must detect A has more work and switch chains even while mining
T_CONN2=$(date +%s)
echo ""
echo "  Restarting A and C (WITH --mine) — C must adopt A's chain while mining..."

"$BIN" --data-dir "$S2A" --p2p-listen 0.0.0.0:19041 --rpc-listen 127.0.0.1:18041 \
    --mine --testnet >"$L2A" 2>&1 &
P2A=$!; ALL_PIDS+=($P2A)
wait_alive "$RPC_A" A

"$BIN" --data-dir "$S2C" --p2p-listen 0.0.0.0:19043 --rpc-listen 127.0.0.1:18043 \
    --mine --testnet --seed 127.0.0.1:19041 --testnet >"$L2C" 2>&1 &
P2C=$!; ALL_PIDS+=($P2C)
wait_alive "$RPC_C" C

if wait_converge "$RPC_A" "$RPC_C" "S2 A+C" 60; then
    SECS2=$(( $(date +%s) - T_CONN2 ))
    ok "S2 A+C converged in ${SECS2}s"
    [ "$SECS2" -le 30 ] && ok "S2 fast convergence (≤30s, got ${SECS2}s)" \
                        || fail "S2 slow convergence (>30s, got ${SECS2}s)"
    FA2=$(height "$RPC_A"); FC2=$(height "$RPC_C")
    # Check convergence at FH-2 (not the tip) so both nodes have had time
    # to commit that block — avoids false positives while both are actively mining.
    FH=$(( FA2 < FC2 ? FA2 : FC2 ))
    FH_STABLE=$(( FH > 2 ? FH - 2 : FH ))
    SAME=$([ "$(hash_at "$RPC_A" "$FH_STABLE")" = "$(hash_at "$RPC_C" "$FH_STABLE")" ] && echo yes || echo no)
    [ "$SAME" = "yes" ] \
        && ok "S2 same block at h=$FH_STABLE (tip-2)" \
        || fail "S2 different blocks at h=$FH_STABLE"
    [ "$FC2" -ge "$H2_A" ] 2>/dev/null \
        && ok "S2 C adopted A's chain (C h=$FC2 ≥ A-before-reconnect h=$H2_A)" \
        || fail "S2 C not at A's level (C h=$FC2 vs A h=$H2_A)"
    SR=$(count_log "sync_ready.*new chain tip\|sealed-state" "$L2C")
    DF=$(count_log "deep fork\|requesting snapshot directly\|O(1) Paranoid sync" "$L2C")
    echo "  sync_ready/sealed-state in C: $SR"
    echo "  snapshot sync (deep fork) in C: $DF"
    [ "$DF" -gt 0 ] 2>/dev/null && ok "S2 C used O(1) snapshot sync" \
                                  || echo "  INFO: shallow fork used block-by-block reorg"
else
    fail "S2 no convergence in 60s"
    echo "  A=$(best_hash "$RPC_A" | cut -c1-20)"
    echo "  C=$(best_hash "$RPC_C" | cut -c1-20)"
fi

check_no_panic "S2-A" "$L2A"
check_no_panic "S2-C" "$L2C"
kill "$P2A" "$P2C" 2>/dev/null || true
wait "$P2A" "$P2C" 2>/dev/null || true

# =============================================================================
echo ""
echo "======================================================================"
printf "  PASS: %d   FAIL: %d\n" "$PASS" "$FAIL"
echo "======================================================================"
[ "$FAIL" -eq 0 ] && echo "  ALL PASSED ✓" && exit 0 || echo "  SOME FAILED ✗" && exit 1

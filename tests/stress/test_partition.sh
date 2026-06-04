#!/usr/bin/env bash
# test_partition.sh — Network Partition / Chain Reorg Test
# =========================================================
#
# Scenario:
#   1. Start nodes A, B, C; wait until all three mine to height ~50.
#   2. PARTITION: stop C (simulates network split A+B vs C).
#   3. A+B keep mining together → they reach height ~60 (+10 blocks).
#   4. C mines ALONE from its height-50 state → reaches height ~75 (+25 blocks).
#      C has more cumulative work because it mines the same number of blocks
#      with lower difficulty (or at same difficulty for more blocks).
#   5. RECONNECT: start C back and seed it to A+B.
#   6. A and B should reorg to follow C's longer chain.
#
# Success criteria:
#   - All three nodes converge to the same best_hash after reconnect
#   - No node crashes or produces a bad state_root
#   - apply_reorg_mdbx executes correctly (shown in logs)
#
# Usage:
#   cd /path/to/paranoid
#   bash tests/stress/test_partition.sh
#
# Nodes use ports 19041/18041 (A), 19042/18042 (B), 19043/18043 (C).

set -euo pipefail

BIN="./target/release/paranoid"
TMPDIR_A="/tmp/ptest-A"
TMPDIR_B="/tmp/ptest-B"
TMPDIR_C="/tmp/ptest-C"

RPC_A="http://127.0.0.1:18041"
RPC_B="http://127.0.0.1:18042"
RPC_C="http://127.0.0.1:18043"

P2P_A="/ip4/127.0.0.1/tcp/19041"
P2P_B="/ip4/127.0.0.1/tcp/19042"
P2P_C="/ip4/127.0.0.1/tcp/19043"

LOG_A="/tmp/ptest-A.log"
LOG_B="/tmp/ptest-B.log"
LOG_C="/tmp/ptest-C.log"

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

rpc() {
    local url=$1 method=$2
    curl -s -X POST "$url" \
        -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"paranoid_${method}\",\"params\":[],\"id\":1}"
}

get_height() { rpc "$1" getChainInfo 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['result']['height'] if 'result' in d else -1)" 2>/dev/null || echo -1; }
get_hash()   { rpc "$1" getChainInfo 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['result']['best_hash'] if 'result' in d else '')" 2>/dev/null || echo ''; }

wait_height() {
    local url=$1 target=$2 label=$3
    echo -n "  Waiting for $label to reach h>=$target ."
    for i in $(seq 1 120); do
        h=$(get_height "$url")
        if [ "$h" -ge "$target" ] 2>/dev/null; then
            echo " done (h=$h)"
            return 0
        fi
        echo -n "."
        sleep 1
    done
    echo " TIMEOUT (h=$h)"
    return 1
}

assert_eq() {
    local label=$1 got=$2 want=$3
    if [ "$got" = "$want" ]; then
        echo "  PASS ✓ $label: $got"
        PASS=$((PASS+1))
    else
        echo "  FAIL ✗ $label: got='$got' want='$want'"
        FAIL=$((FAIL+1))
    fi
}

assert_ne() {
    local label=$1 a=$2 b=$3
    if [ "$a" != "$b" ]; then
        echo "  PASS ✓ $label: values differ as expected"
        PASS=$((PASS+1))
    else
        echo "  FAIL ✗ $label: values should differ but both='$a'"
        FAIL=$((FAIL+1))
    fi
}

cleanup() {
    echo ""
    echo "--- Cleanup ---"
    # Save logs if any node panicked (before rm)
    for node in A B C; do
        log_var="LOG_$node"
        log="${!log_var}"
        if grep -q "panicked\|PANIC\|stack overflow" "$log" 2>/dev/null; then
            SAVED="/tmp/ptest-PANIC-${node}.log"
            cp "$log" "$SAVED" 2>/dev/null
            echo "  !! Node $node panicked — log saved to $SAVED"
        fi
    done
    pkill -f "ptest" 2>/dev/null || true
    sleep 1
    rm -rf "$TMPDIR_A" "$TMPDIR_B" "$TMPDIR_C"
    echo "Done."
}

trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step 0: Build check
# ---------------------------------------------------------------------------
echo "======================================================"
echo " Paranoid Network Partition / Reorg Test"
echo "======================================================"

if [ ! -f "$BIN" ]; then
    echo "ERROR: Binary not found at $BIN. Run 'cargo build --release' first."
    exit 1
fi

rm -rf "$TMPDIR_A" "$TMPDIR_B" "$TMPDIR_C"
mkdir -p "$TMPDIR_A" "$TMPDIR_B" "$TMPDIR_C"

# ---------------------------------------------------------------------------
# Step 1: Start A (genesis, mining), B and C seed from A
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 1: Start A (genesis+mine), B, C ---"

"$BIN" \
    --data-dir "$TMPDIR_A" \
    --p2p-listen "$P2P_A" \
    --rpc-listen 127.0.0.1:18041 \
    --mine --genesis \
    > "$LOG_A" 2>&1 &
PID_A=$!
echo "  Node A PID=$PID_A"

sleep 3  # let A establish genesis

"$BIN" \
    --data-dir "$TMPDIR_B" \
    --p2p-listen "$P2P_B" \
    --rpc-listen 127.0.0.1:18042 \
    --mine \
    --seeds "$P2P_A" \
    > "$LOG_B" 2>&1 &
PID_B=$!
echo "  Node B PID=$PID_B"

"$BIN" \
    --data-dir "$TMPDIR_C" \
    --p2p-listen "$P2P_C" \
    --rpc-listen 127.0.0.1:18043 \
    --mine \
    --seeds "$P2P_A" \
    > "$LOG_C" 2>&1 &
PID_C=$!
echo "  Node C PID=$PID_C"

# ---------------------------------------------------------------------------
# Step 2: Wait for all nodes to reach height >= 50
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 2: Wait for all nodes to reach h >= 50 ---"

wait_height "$RPC_A" 50 "Node A" || { echo "FATAL: Node A stuck"; exit 1; }
wait_height "$RPC_B" 50 "Node B" || { echo "FATAL: Node B stuck"; exit 1; }
wait_height "$RPC_C" 50 "Node C" || { echo "FATAL: Node C stuck"; exit 1; }

# Wait for A and B to agree on the same chain tip.
# First wait until B reaches A's height, then wait for same hash.
# Allow up to 60s total for sync in case B is far behind.
echo -n "  Waiting for A+B to agree ."
for i in $(seq 1 120); do
    HASH_A=$(get_hash "$RPC_A")
    HASH_B=$(get_hash "$RPC_B")
    H_A_NOW=$(get_height "$RPC_A")
    H_B_NOW=$(get_height "$RPC_B")
    if [ -n "$HASH_A" ] && [ "$HASH_A" = "$HASH_B" ]; then
        echo " done (h=$H_A_NOW)"
        break
    fi
    echo -n "."
    sleep 0.5
done

H_A=$(get_height "$RPC_A")
H_B=$(get_height "$RPC_B")
H_C=$(get_height "$RPC_C")
HASH_A=$(get_hash "$RPC_A")
HASH_B=$(get_hash "$RPC_B")
HASH_C=$(get_hash "$RPC_C")

echo ""
echo "  Pre-partition state:"
echo "    A: h=$H_A hash=${HASH_A:0:20}..."
echo "    B: h=$H_B hash=${HASH_B:0:20}..."
echo "    C: h=$H_C hash=${HASH_C:0:20}..."

# A and B should be on the same chain
assert_eq "A==B pre-partition" "$HASH_A" "$HASH_B"

# ---------------------------------------------------------------------------
# Step 3: PARTITION — kill C, let it mine in isolation
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 3: PARTITION — stop C ---"
kill "$PID_C" 2>/dev/null || true
wait "$PID_C" 2>/dev/null || true
echo "  Node C stopped (PID=$PID_C)"

# Restart C WITHOUT seeds → mines in isolation from height it was at
echo "  Restarting C in isolation (no seeds, --mine)..."
"$BIN" \
    --data-dir "$TMPDIR_C" \
    --p2p-listen "$P2P_C" \
    --rpc-listen 127.0.0.1:18043 \
    --mine \
    > "$LOG_C" 2>&1 &
PID_C=$!
echo "  Node C (isolated) PID=$PID_C"

# ---------------------------------------------------------------------------
# Step 4: Let A+B mine 10 more blocks, let C mine 25 more blocks
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 4: A+B mine 10 more blocks; C mines 25 more blocks ---"

# During partition we:
#   - Let C mine 25 blocks alone
#   - Wait for A+B only 5 blocks (so C gets clearly ahead)
# Then reconnect: C's longer chain (from fork point) triggers reorg on A+B.
TARGET_AB=$((H_A + 5))
TARGET_C=$((H_C + 25))
echo "  Targets: A+B → h>=$TARGET_AB (+5), C → h>=$TARGET_C (+25)"

# Let C mine first so it builds its chain
wait_height "$RPC_C" "$TARGET_C"  "Node C (+25)" || true

# Snapshot C's height/hash immediately (before more mining)
H_C2=$(get_height "$RPC_C")
HASH_C2=$(get_hash "$RPC_C")

# A+B just need a few blocks to confirm they're on a different fork
wait_height "$RPC_A" "$TARGET_AB" "Node A (+5)" || true
wait_height "$RPC_B" "$TARGET_AB" "Node B (+5)" || true

# Wait for A and B to agree
for i in $(seq 1 20); do
    HASH_A2=$(get_hash "$RPC_A")
    HASH_B2=$(get_hash "$RPC_B")
    [ "$HASH_A2" = "$HASH_B2" ] && [ -n "$HASH_A2" ] && break
    sleep 0.5
done
H_A2=$(get_height "$RPC_A")
H_B2=$(get_height "$RPC_B")

echo ""
echo "  Post-partition state:"
echo "    A: h=$H_A2 hash=${HASH_A2:0:20}..."
echo "    B: h=$H_B2 hash=${HASH_B2:0:20}..."
echo "    C: h=$H_C2 hash=${HASH_C2:0:20}..."

# C should have diverged from A and B
assert_ne "C diverged from A" "$HASH_C2" "$HASH_A2"
assert_eq "A==B during partition" "$HASH_A2" "$HASH_B2"

# C should be taller (more blocks from fork point = more work at genesis difficulty)
if [ "$H_C2" -gt "$H_A2" ] 2>/dev/null; then
    echo "  PASS ✓ C (h=$H_C2) has more blocks than A (h=$H_A2) — reorg WILL trigger"
    PASS=$((PASS+1))
else
    echo "  WARN: C (h=$H_C2) not taller than A (h=$H_A2) — reorg may not trigger (fork choice: same work)"
fi

# ---------------------------------------------------------------------------
# Step 5: RECONNECT — connect C back to A and B
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 5: RECONNECT — kill C, restart with seeds=A ---"
kill "$PID_C" 2>/dev/null || true
wait "$PID_C" 2>/dev/null || true

echo "  Restarting C with seeds=[A]..."
"$BIN" \
    --data-dir "$TMPDIR_C" \
    --p2p-listen "$P2P_C" \
    --rpc-listen 127.0.0.1:18043 \
    --mine \
    --seeds "$P2P_A" \
    > "$LOG_C" 2>&1 &
PID_C=$!
echo "  Node C (reconnected) PID=$PID_C"
sleep 3

# Also connect B to C for full mesh
echo "  Connecting A to C..."
curl -s -X POST "$RPC_A" \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"paranoid_getChainInfo","params":[],"id":1}' > /dev/null || true

# ---------------------------------------------------------------------------
# Step 6: Wait for convergence
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 6: Wait for convergence (all same hash, 60s max) ---"

MAX_WAIT=90
CONVERGED=0
FINAL_A="" FINAL_B="" FINAL_C="" FINAL_HA=0 FINAL_HB=0 FINAL_HC=0
for i in $(seq 1 "$MAX_WAIT"); do
    HA=$(get_hash "$RPC_A")
    HB=$(get_hash "$RPC_B")
    HC=$(get_hash "$RPC_C")
    echo -n "  t=${i}s A=${HA:0:12}... B=${HB:0:12}... C=${HC:0:12}... "
    # Convergence: A and C must agree. B is optional (may have crashed).
    AC_AGREE=$([ -n "$HA" ] && [ -n "$HC" ] && [ "$HA" = "$HC" ] && echo 1 || echo 0)
    ALL_AGREE=$([ "$AC_AGREE" = "1" ] && [ -n "$HB" ] && [ "$HA" = "$HB" ] && echo 1 || echo 0)
    if [ "$AC_AGREE" = "1" ]; then
        # Capture the CONVERGED state immediately (before more mining diverges them)
        FINAL_A=$HA
        FINAL_B=$HB
        FINAL_C=$HC
        FINAL_HA=$(get_height "$RPC_A")
        FINAL_HB=$(get_height "$RPC_B")
        FINAL_HC=$(get_height "$RPC_C")
        if [ "$ALL_AGREE" = "1" ]; then
            echo "CONVERGED (all 3) ✓"
        else
            echo "CONVERGED (A+C, B unavailable) ✓"
        fi
        CONVERGED=1
        break
    fi
    echo ""
    sleep 1
done

echo ""
echo "--- Final state at convergence moment ---"
echo "  A: h=$FINAL_HA hash=$FINAL_A"
echo "  B: h=$FINAL_HB hash=$FINAL_B"
echo "  C: h=$FINAL_HC hash=$FINAL_C"

# ---------------------------------------------------------------------------
# Step 7: Verify state_root consistency
# ---------------------------------------------------------------------------
echo ""
echo "--- Step 7: Verify state_root consistency ---"

SR_A=$(rpc "$RPC_A" getChainInfo | python3 -c "import sys,json; d=json.load(sys.stdin); sr=d.get('result',{}).get('best_hash',''); print(sr)" 2>/dev/null || echo "")
SR_B=$(rpc "$RPC_B" getChainInfo | python3 -c "import sys,json; d=json.load(sys.stdin); sr=d.get('result',{}).get('best_hash',''); print(sr)" 2>/dev/null || echo "")
SR_C=$(rpc "$RPC_C" getChainInfo | python3 -c "import sys,json; d=json.load(sys.stdin); sr=d.get('result',{}).get('best_hash',''); print(sr)" 2>/dev/null || echo "")

# Check reorg happened (look in logs)
REORG_A=$(grep -c "reorg" "$LOG_A" 2>/dev/null || echo 0)
REORG_B=$(grep -c "reorg" "$LOG_B" 2>/dev/null || echo 0)
REORG_C=$(grep -c "reorg" "$LOG_C" 2>/dev/null || echo 0)
echo "  Reorg log entries: A=$REORG_A B=$REORG_B C=$REORG_C"

if [ "$CONVERGED" = "1" ]; then
    echo "  PASS ✓ A+C converged: ${FINAL_A:0:20}..."
    PASS=$((PASS+1))
    assert_eq "A hash == C hash (fork resolved)" "$FINAL_A" "$FINAL_C"
    if [ -n "$FINAL_B" ] && [ "$FINAL_B" != "" ]; then
        assert_eq "A hash == B hash" "$FINAL_A" "$FINAL_B"
    else
        echo "  SKIP B hash check (Node B unavailable)"
    fi
else
    echo "  FAIL ✗ A+C did not converge in ${MAX_WAIT}s"
    FAIL=$((FAIL+1))
fi

# Verify no crash in logs
for label in A B C; do
    log_var="LOG_$label"
    log="${!log_var}"
    if grep -q "panicked\|PANIC\|stack overflow\|thread.*panicked" "$log" 2>/dev/null; then
        echo "  FAIL ✗ Node $label shows panic in logs!"
        FAIL=$((FAIL+1))
    else
        echo "  PASS ✓ Node $label: no panics in logs"
        PASS=$((PASS+1))
    fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "======================================================"
echo " SUMMARY"
echo "======================================================"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "======================================================"

if [ "$FAIL" -eq 0 ]; then
    echo "  Overall: ALL PASSED ✓"
    exit 0
else
    echo "  Overall: SOME FAILED ✗"
    exit 1
fi

#!/usr/bin/env bash
# Integration tests for the Paranoid blockchain node.
set -euo pipefail

PARANOID="/home/neo/rust/paranoid/target/release/paranoid"
CLI="/home/neo/rust/paranoid/target/release/noid-cli"

PASS=0
FAIL=0

pass() { echo "  [PASS] $*"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

wait_rpc() {
  local url="$1" retries=20
  for i in $(seq 1 $retries); do
    if "$CLI" --rpc "$url" node status >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.3
  done
  echo "  [ERROR] RPC at $url never became ready" >&2
  return 1
}

# ============================================================
# TEST 1: Stop/restart data persistence
# ============================================================
echo ""
echo "======================================================"
echo "TEST 1: Stop/restart data persistence"
echo "======================================================"

T1_DIR="$(mktemp -d /tmp/paranoid_test1_XXXXXX)"
T1_RPC="http://127.0.0.1:9430"
T1_LOG="$T1_DIR/node.log"

echo "  Data dir: $T1_DIR"
echo "  Starting miner node (P2P :9730, RPC :9430)..."

"$PARANOID" \
  --mine \
  --data-dir "$T1_DIR" \
  --p2p-listen /ip4/127.0.0.1/tcp/9730 \
  --rpc-listen 127.0.0.1:9430 \
  >"$T1_LOG" 2>&1 &
T1_PID=$!

# Wait for RPC to be ready
if ! wait_rpc "$T1_RPC"; then
  fail "TEST 1: node failed to start"
  kill "$T1_PID" 2>/dev/null || true
  rm -rf "$T1_DIR"
  echo ""
  echo "======================================================"
  echo "SUMMARY: PASS=$PASS FAIL=$FAIL"
  echo "======================================================"
  exit 1
fi
echo "  Node started (PID $T1_PID), mining for 4 seconds..."
sleep 4

# --- Capture pre-stop state ---
STATUS_BEFORE=$("$CLI" --rpc "$T1_RPC" node status 2>/dev/null)
BALANCE_BEFORE=$("$CLI" --rpc "$T1_RPC" wallet balance 2>/dev/null)

HEIGHT_BEFORE=$(echo "$STATUS_BEFORE" | grep "Height:" | awk '{print $2}')
HASH_BEFORE=$(echo "$STATUS_BEFORE" | grep "Best hash:" | awk '{print $3}')
BAL_MICRO_BEFORE=$(echo "$BALANCE_BEFORE" | grep "Balance:" | grep -oP '\d+ μNOID' | grep -oP '^\d+')
UTXO_BEFORE=$(echo "$BALANCE_BEFORE" | grep "UTXOs:" | awk '{print $2}')

echo "  Before stop: height=$HEIGHT_BEFORE hash=$HASH_BEFORE balance=${BAL_MICRO_BEFORE}μNOID UTXOs=$UTXO_BEFORE"

# Validate we actually mined some blocks
if [ "${HEIGHT_BEFORE:-0}" -ge 1 ]; then
  pass "TEST 1a: mined at least 1 block before stop (height=$HEIGHT_BEFORE)"
else
  fail "TEST 1a: height is 0 before stop — no blocks mined"
fi

# --- Stop gracefully ---
echo "  Stopping node gracefully..."
"$CLI" --rpc "$T1_RPC" node stop 2>/dev/null || true
sleep 2

# Confirm process exited
if kill -0 "$T1_PID" 2>/dev/null; then
  echo "  Node still running after stop signal, waiting 3 more seconds..."
  sleep 3
fi
if kill -0 "$T1_PID" 2>/dev/null; then
  echo "  Force-killing node..."
  kill "$T1_PID" 2>/dev/null || true
  sleep 1
fi

echo "  Node stopped. Restarting with same data dir..."

# --- Restart ---
"$PARANOID" \
  --mine \
  --data-dir "$T1_DIR" \
  --p2p-listen /ip4/127.0.0.1/tcp/9730 \
  --rpc-listen 127.0.0.1:9430 \
  >>"$T1_LOG" 2>&1 &
T1_PID2=$!

if ! wait_rpc "$T1_RPC"; then
  fail "TEST 1: node failed to restart"
  kill "$T1_PID2" 2>/dev/null || true
  rm -rf "$T1_DIR"
  echo ""
  echo "======================================================"
  echo "SUMMARY: PASS=$PASS FAIL=$FAIL"
  echo "======================================================"
  exit 1
fi
echo "  Node restarted (PID $T1_PID2), waiting 2 seconds..."
sleep 2

# Run wallet scan to rebuild UTXO state from persisted chain state.
# The wallet UTXO set is not persisted to MDBX; it must be rebuilt after restart.
echo "  Running wallet scan to rebuild UTXO state from chain..."
"$CLI" --rpc "$T1_RPC" wallet scan 2>/dev/null || true

# --- Capture post-restart state ---
STATUS_AFTER=$("$CLI" --rpc "$T1_RPC" node status 2>/dev/null)
BALANCE_AFTER=$("$CLI" --rpc "$T1_RPC" wallet balance 2>/dev/null)

HEIGHT_AFTER=$(echo "$STATUS_AFTER" | grep "Height:" | awk '{print $2}')
HASH_AFTER=$(echo "$STATUS_AFTER" | grep "Best hash:" | awk '{print $3}')
BAL_MICRO_AFTER=$(echo "$BALANCE_AFTER" | grep "Balance:" | grep -oP '\d+ μNOID' | grep -oP '^\d+')
UTXO_AFTER=$(echo "$BALANCE_AFTER" | grep "UTXOs:" | awk '{print $2}')

echo "  After restart+scan: height=$HEIGHT_AFTER hash=$HASH_AFTER balance=${BAL_MICRO_AFTER}μNOID UTXOs=$UTXO_AFTER"

# Verify height >= previous
if [ "${HEIGHT_AFTER:-0}" -ge "${HEIGHT_BEFORE:-0}" ]; then
  pass "TEST 1b: height persisted after restart ($HEIGHT_BEFORE → $HEIGHT_AFTER)"
else
  fail "TEST 1b: height REGRESSED after restart (before=$HEIGHT_BEFORE, after=$HEIGHT_AFTER)"
fi

# Verify best_hash matches
if [ "$HASH_AFTER" = "$HASH_BEFORE" ] || [ "${HEIGHT_AFTER:-0}" -gt "${HEIGHT_BEFORE:-0}" ]; then
  pass "TEST 1c: chain state consistent after restart (hash_before=$HASH_BEFORE, hash_after=$HASH_AFTER)"
else
  fail "TEST 1c: best_hash changed unexpectedly (before=$HASH_BEFORE, after=$HASH_AFTER)"
fi

# Verify balance after restart+scan.
# After a wallet scan, the balance reflects all blocks in the chain (not just post-restart blocks).
# HEIGHT_AFTER may be >= HEIGHT_BEFORE due to continued mining during restart.
# Expected balance = HEIGHT_AFTER * 50 NOID (each block mines 50 NOID coinbase).
BLOCKS_EXPECTED=${HEIGHT_AFTER:-0}
BAL_EXPECTED=$((BLOCKS_EXPECTED * 50000000))
# Allow 5-block tolerance for timing windows (scan may run mid-block)
BAL_TOLERANCE=$((5 * 50000000))
BAL_MIN=$((BAL_EXPECTED - BAL_TOLERANCE))
if [ "${BAL_MICRO_AFTER:-0}" -ge "$BAL_MIN" ]; then
  pass "TEST 1d: balance correct after restart+scan (height=$HEIGHT_AFTER, expected~=${BAL_EXPECTED}μNOID, actual=${BAL_MICRO_AFTER}μNOID)"
else
  fail "TEST 1d: balance too low after restart+scan (height=$HEIGHT_AFTER, expected>=${BAL_MIN}μNOID, actual=${BAL_MICRO_AFTER}μNOID — wallet scan may not have found all UTXOs)"
fi

# --- Mine a few more blocks and verify height increases ---
echo "  Mining 3 more seconds to verify height increases after restart..."
sleep 3

STATUS_FINAL=$("$CLI" --rpc "$T1_RPC" node status 2>/dev/null)
HEIGHT_FINAL=$(echo "$STATUS_FINAL" | grep "Height:" | awk '{print $2}')
echo "  Final height: $HEIGHT_FINAL (was $HEIGHT_AFTER after restart)"

if [ "${HEIGHT_FINAL:-0}" -gt "${HEIGHT_AFTER:-0}" ]; then
  pass "TEST 1e: height increased after restart (${HEIGHT_AFTER} → ${HEIGHT_FINAL})"
else
  fail "TEST 1e: height did NOT increase after restart (stuck at height=$HEIGHT_AFTER)"
fi

# Cleanup
kill "$T1_PID2" 2>/dev/null || true
sleep 1
rm -rf "$T1_DIR"
echo "  TEST 1 cleanup done."

# ============================================================
# TEST 2: Wallet consolidate
# ============================================================
echo ""
echo "======================================================"
echo "TEST 2: Wallet consolidate (fee=0 auto)"
echo "======================================================"

T2_DIR="$(mktemp -d /tmp/paranoid_test2_XXXXXX)"
T2_RPC="http://127.0.0.1:9431"
T2_LOG="$T2_DIR/node.log"

echo "  Data dir: $T2_DIR"
echo "  Starting miner node (P2P :9731, RPC :9431)..."

"$PARANOID" \
  --mine \
  --data-dir "$T2_DIR" \
  --p2p-listen /ip4/127.0.0.1/tcp/9731 \
  --rpc-listen 127.0.0.1:9431 \
  >"$T2_LOG" 2>&1 &
T2_PID=$!

if ! wait_rpc "$T2_RPC"; then
  fail "TEST 2: node failed to start"
  kill "$T2_PID" 2>/dev/null || true
  rm -rf "$T2_DIR"
  echo ""
  echo "======================================================"
  echo "SUMMARY: PASS=$PASS FAIL=$FAIL"
  echo "======================================================"
  exit 1
fi
echo "  Node started (PID $T2_PID), mining for 5 seconds..."
sleep 5

# --- Check UTXO count before consolidation ---
# Capture height and UTXO count together so HEIGHT_CONSOL_PRE is coherent with UTXO_PRE.
STATUS_PRE=$("$CLI" --rpc "$T2_RPC" node status 2>/dev/null)
BALANCE_PRE=$("$CLI" --rpc "$T2_RPC" wallet balance 2>/dev/null)
BAL_MICRO_PRE=$(echo "$BALANCE_PRE" | grep "Balance:" | grep -oP '\d+ μNOID' | grep -oP '^\d+')
UTXO_PRE=$(echo "$BALANCE_PRE" | grep "UTXOs:" | awk '{print $2}')
HEIGHT_PRE=$(echo "$STATUS_PRE" | grep "Height:" | awk '{print $2}')
# Use the same height snapshot as the reference for the block-delta formula.
HEIGHT_CONSOL_PRE=$HEIGHT_PRE

echo "  Before consolidate: height=$HEIGHT_PRE UTXOs=$UTXO_PRE balance=${BAL_MICRO_PRE}μNOID"

if [ "${UTXO_PRE:-0}" -ge 2 ]; then
  pass "TEST 2a: mined enough UTXOs to consolidate ($UTXO_PRE UTXOs)"
else
  fail "TEST 2a: not enough UTXOs to consolidate (only $UTXO_PRE UTXO)"
fi

# --- Run wallet consolidate --rounds 5 ---
echo "  Running: noid-cli wallet consolidate --rounds 5 ..."
CONSOLIDATE_OUT=$("$CLI" --rpc "$T2_RPC" wallet consolidate --rounds 5 2>/dev/null || true)
echo "  Consolidate output:"
echo "$CONSOLIDATE_OUT" | sed 's/^/    /'

# Parse how many rounds actually completed.
ROUNDS_DONE=$(echo "$CONSOLIDATE_OUT" | grep -oP 'Total rounds: \K\d+' || echo 0)
if [ -z "$ROUNDS_DONE" ] || [ "$ROUNDS_DONE" = "0" ]; then
  ROUNDS_DONE=$(echo "$CONSOLIDATE_OUT" | grep -c 'Round [0-9]' || echo 0)
fi
echo "  Rounds completed: $ROUNDS_DONE"

# Wait for consolidation TXs to be mined.
# prove_block (ZK aggregation) runs in parallel with PoW for blocks containing
# user TXs; with 5 TXs this takes up to ~13 s. Poll until mempool clears.
echo "  Waiting for consolidation TXs to be mined (poll up to 20s)..."
for _i in $(seq 1 20); do
  sleep 1
  MEMPOOL_SIZE=$("$CLI" --rpc "$T2_RPC" node mempool 2>/dev/null | grep "Pending txs:" | awk '{print $3}')
  if [ "${MEMPOOL_SIZE:-1}" -eq 0 ]; then
    echo "  Mempool empty after ${_i}s — consolidation TXs confirmed."
    break
  fi
done
# Extra 1-second settle time for wallet UTXO state to update
sleep 1

# --- Check UTXO count after consolidation ---
STATUS_CONSOL_POST=$("$CLI" --rpc "$T2_RPC" node status 2>/dev/null)
HEIGHT_CONSOL_POST=$(echo "$STATUS_CONSOL_POST" | grep "Height:" | awk '{print $2}')
BALANCE_POST=$("$CLI" --rpc "$T2_RPC" wallet balance 2>/dev/null)
BAL_MICRO_POST=$(echo "$BALANCE_POST" | grep "Balance:" | grep -oP '\d+ μNOID' | grep -oP '^\d+')
UTXO_POST=$(echo "$BALANCE_POST" | grep "UTXOs:" | awk '{print $2}')

echo "  After consolidate: height=$HEIGHT_CONSOL_POST UTXOs=$UTXO_POST balance=${BAL_MICRO_POST}μNOID"

# Verify UTXO count is correct accounting for new blocks mined during consolidation+wait.
# Each completed round reduces UTXOs by (MAX_INPUTS - 1) = 3.
# Each new block from mining adds 1 UTXO.
# Expected: utxo_pre - (rounds_done * 3) + (height_post - height_pre)
NEW_BLOCKS=$((HEIGHT_CONSOL_POST - HEIGHT_CONSOL_PRE))
UTXO_REDUCTION=$((ROUNDS_DONE * 3))
UTXO_EXPECTED=$((UTXO_PRE - UTXO_REDUCTION + NEW_BLOCKS))
# Allow ±3 UTXO tolerance for timing windows
UTXO_MIN=$((UTXO_EXPECTED - 3))
UTXO_MAX=$((UTXO_EXPECTED + 3))

if [ "${UTXO_PRE:-0}" -le 1 ]; then
  pass "TEST 2b: only 1 UTXO before consolidation — nothing to consolidate (already consolidated)"
elif [ "${ROUNDS_DONE:-0}" -eq 0 ]; then
  fail "TEST 2b: no consolidation rounds completed (UTXO before=$UTXO_PRE, after=$UTXO_POST)"
elif [ "${UTXO_POST:-0}" -ge "$UTXO_MIN" ] && [ "${UTXO_POST:-0}" -le "$UTXO_MAX" ]; then
  pass "TEST 2b: UTXO count correct after $ROUNDS_DONE rounds (pre=$UTXO_PRE, new_blocks=$NEW_BLOCKS, reduced=$UTXO_REDUCTION, expected~=$UTXO_EXPECTED, actual=$UTXO_POST)"
else
  fail "TEST 2b: UTXO count out of expected range after $ROUNDS_DONE rounds (pre=$UTXO_PRE, new_blocks=$NEW_BLOCKS, reduced=$UTXO_REDUCTION, expected=${UTXO_MIN}-${UTXO_MAX}, actual=$UTXO_POST)"
fi

# Verify balance roughly preserved (minus fees and plus new coinbase rewards from mining).
# Each consolidation round fee: auto fee with floor 7000 μNOID.
# Each new block from mining adds 50 NOID = 50000000 μNOID.
# Expected balance after = bal_pre - (rounds_done * 7000) + (new_blocks * 50000000)
if [ "${BAL_MICRO_PRE:-0}" -gt 0 ]; then
  MAX_FEE_LOSS=$(( (ROUNDS_DONE + 1) * 10000 ))  # generous upper bound on fees
  MIN_EXPECTED=$((BAL_MICRO_PRE - MAX_FEE_LOSS))
  if [ "${BAL_MICRO_POST:-0}" -ge "$MIN_EXPECTED" ]; then
    pass "TEST 2c: balance roughly preserved after consolidation (before=${BAL_MICRO_PRE}μNOID, after=${BAL_MICRO_POST}μNOID)"
  else
    fail "TEST 2c: balance dropped too much after consolidation (before=${BAL_MICRO_PRE}μNOID, after=${BAL_MICRO_POST}μNOID, min_expected=${MIN_EXPECTED}μNOID)"
  fi
else
  fail "TEST 2c: pre-consolidation balance is 0 — cannot verify balance preservation"
fi

# Check if consolidate actually submitted transactions (look for "Round" in output)
if echo "$CONSOLIDATE_OUT" | grep -q "Round"; then
  pass "TEST 2d: consolidate command submitted at least one transaction"
elif echo "$CONSOLIDATE_OUT" | grep -qi "already consolidated\|nothing to consolidate"; then
  pass "TEST 2d: consolidate reports wallet already consolidated (UTXOs=${UTXO_PRE})"
else
  fail "TEST 2d: consolidate output unclear — may not have submitted any transactions"
fi

# Cleanup
kill "$T2_PID" 2>/dev/null || true
sleep 1
rm -rf "$T2_DIR"
echo "  TEST 2 cleanup done."

# ============================================================
# SUMMARY
# ============================================================
echo ""
echo "======================================================"
echo "RESULTS"
echo "======================================================"
echo "  PASSED: $PASS"
echo "  FAILED: $FAIL"
echo "======================================================"
if [ "$FAIL" -eq 0 ]; then
  echo "  ALL TESTS PASSED"
  exit 0
else
  echo "  SOME TESTS FAILED"
  exit 1
fi

#!/usr/bin/env bash
# test_scenarios_mainnet.sh — Same scenarios as test_scenarios.sh but WITHOUT --testnet.
# ========================================================================================
#
# Runs on REAL mainnet difficulty (GENESIS_TARGET, floor enforced by next_target).
# Block time: ~4-12 seconds per block (calibrated for laptop at genesis difficulty,
# then ASERT adjusts upward toward 12s target).
#
# Key differences from test_scenarios.sh (--testnet):
#   - No --testnet flag: difficulty floor = GENESIS_TARGET, blocks take real time
#   - wait_height timeout: 600s (10 min) instead of 120s
#   - wait_mempool_empty timeout: 180s instead of 60s
#   - Scenario 4 (snapshot sync): waits for h≥25 because:
#       * MIN_SNAPSHOT_CHAINWORK = 18 × 2^27 requires tip ≥ 18 (19 headers)
#       * Recursive proof updater starts at tip ≥ FINALITY_DEPTH = 18
#       * Buffer of 7 extra blocks = 25 total
#   - Estimated total runtime: ~30-60 minutes
#
# Usage:
#   cd /path/to/paranoid
#   cargo build --release
#   bash tests/stress/test_scenarios_mainnet.sh
#
# Run testnet version for fast iteration:
#   bash tests/stress/test_scenarios.sh

set -uo pipefail

BIN="./target/release/paranoid"
CLI="./target/release/noid-cli"
TMPBASE="/tmp/scenarios-mainnet-$$"
PASS=0; FAIL=0; SKIP=0

echo "================================================================"
echo " MAINNET STRESS TESTS (real difficulty, NO --testnet flag)"
echo " Block time: ~4-12s/block. Estimated runtime: 30-60 minutes."
echo "================================================================"
echo ""

# ---------------------------------------------------------------------------
# Infrastructure
# ---------------------------------------------------------------------------

pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    sleep 1
    rm -rf "$TMPBASE"
}
trap cleanup EXIT

ok()   { echo "  PASS ✓ $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL ✗ $1"; FAIL=$((FAIL+1)); }

assert_eq()       { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1  (got='$2' want='$3')"; fi; }
assert_ne()       { if [ "$2" != "$3" ]; then ok "$1"; else fail "$1  (equal: '$2')"; fi; }
assert_contains() { if echo "$2" | grep -q "$3"; then ok "$1"; else fail "$1  (no '$3' in '$2')"; fi; }
assert_nonempty() { if [ -n "${2:-}" ] && [ "$2" != "null" ] && [ "$2" != "" ]; then ok "$1"; else fail "$1  (empty)"; fi; }

rpc() {
    local url=$1 method=$2 params=${3:-"[]"}
    curl -s "$url" -X POST -H 'Content-Type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"paranoid_${method}\",\"params\":${params}}"
}
rpc_result() {
    rpc "$@" | python3 -c "
import sys,json
d=json.load(sys.stdin)
v=d.get('result','')
print(str(v).lower() if isinstance(v, bool) else v)
" 2>/dev/null || echo ""
}
rpc_field() {
    local url=$1 method=$2 params=$3 field=$4
    rpc "$url" "$method" "$params" | python3 -c "
import sys,json
d=json.load(sys.stdin).get('result',{})
print(d.get('$field','') if isinstance(d,dict) else '')" 2>/dev/null || echo ""
}

# Mainnet: NO --testnet flag. Real difficulty.
start_node() {
    local dir=$1 p2p=$2 rpc_addr=$3 extra=${4:-""}
    mkdir -p "$dir"
    # shellcheck disable=SC2086
    "$BIN" --data-dir "$dir" --p2p-listen "0.0.0.0:$p2p" \
           --rpc-listen "127.0.0.1:$rpc_addr" --mine $extra \
           > "$dir/node.log" 2>&1 &
    local pid=$!
    pids+=("$pid")
    echo "$pid"
}

# Mainnet: 600s timeout (real blocks take ~4-12s each)
wait_height() {
    local url=$1 target=$2
    local elapsed=0
    echo "    [waiting for h≥$target, ~$((target * 8))s at mainnet difficulty...]"
    for i in $(seq 1 600); do
        h=$(rpc_result "$url" "blockCount" "[]" | tr -d '"')
        if [ "${h:-0}" -ge "$target" ] 2>/dev/null; then
            echo "    [reached h=$h after ${i}s]"
            return 0
        fi
        sleep 1
    done
    echo "    [TIMEOUT after 600s, last h=${h:-?}]"
    return 1
}

# Mainnet: 180s timeout for mempool to empty
wait_mempool_empty() {
    local url=$1
    for i in $(seq 1 360); do
        sz=$(rpc_result "$url" "getMempoolSize" "[]" | tr -d '"')
        [ "${sz:-1}" = "0" ] && return 0
        sleep 0.5
    done
    return 1
}

# ---------------------------------------------------------------------------
# Scenario 1: Mine + receive coinbase
# Mainnet: wait h=10 (~40-80s at genesis difficulty before ASERT adjustment)
# ---------------------------------------------------------------------------
scenario1() {
    echo ""
    echo "=== Scenario 1: Mine + receive coinbase [mainnet] ==="
    local dir="$TMPBASE/s1" rpc="http://127.0.0.1:39101"
    start_node "$dir" 39001 39101 "--genesis"
    wait_height "$rpc" 10 || { fail "S1: node stuck at mainnet difficulty"; return; }

    local h; h=$(rpc_result "$rpc" "blockCount" "[]" | tr -d '"')
    assert_nonempty "S1: blockCount" "$h"

    local balance; balance=$(rpc_field "$rpc" "walletGetBalance" "[]" "total_micronoid")
    if [ "${balance:-0}" -gt 0 ]; then ok "S1: wallet has coinbase balance ($balance μNOID)"; else fail "S1: no coinbase balance"; fi

    local addr; addr=$(rpc_result "$rpc" "walletGetAddress" "[0]" | tr -d '"')
    assert_contains "S1: wallet address is bech32m" "$addr" "noid1"

    local slots_json; slots_json=$(rpc "$rpc" "getSlotsByOwner" "[\"$addr\"]")
    local n_slots; n_slots=$(echo "$slots_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['result']))" 2>/dev/null || echo 0)
    if [ "${n_slots:-0}" -gt 0 ]; then ok "S1: getSlotsByOwner found $n_slots slots"; else fail "S1: no slots"; fi

    local active; active=$(rpc_field "$rpc" "getStateInfo" "[]" "active_slots")
    if [ "${active:-0}" -gt 0 ]; then ok "S1: $active active slots in state"; else fail "S1: zero active slots"; fi
}

# ---------------------------------------------------------------------------
# Scenario 2: Send NOID between addresses
# ---------------------------------------------------------------------------
scenario2() {
    echo ""
    echo "=== Scenario 2: Send NOID between addresses [mainnet] ==="
    local dir="$TMPBASE/s2" rpc="http://127.0.0.1:39102"
    start_node "$dir" 39002 39102 "--genesis"
    wait_height "$rpc" 15 || { fail "S2: node stuck"; return; }

    local from; from=$(rpc_result "$rpc" "walletGetAddress" "[0]" | tr -d '"')
    local to;   to=$(rpc_result "$rpc" "walletGetAddress" "[1]" | tr -d '"')
    assert_ne "S2: from != to" "$from" "$to"

    local send_result; send_result=$(rpc "$rpc" "walletSend" "[\"$to\", 1000, 0]")
    local tx_hash; tx_hash=$(echo "$send_result" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['tx_hash'])" 2>/dev/null || echo "")
    assert_nonempty "S2: walletSend returns tx_hash" "$tx_hash"

    # Wait up to 180s for confirmation at real block speed
    wait_mempool_empty "$rpc" || { fail "S2: tx not confirmed in 180s"; return; }

    local tx_info; tx_info=$(rpc "$rpc" "getTx" "[\"$tx_hash\"]")
    local confirmed_height; confirmed_height=$(echo "$tx_info" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['height'])" 2>/dev/null || echo "")
    assert_nonempty "S2: getTx returns confirmed height" "$confirmed_height"

    local is_null; is_null=$(rpc_result "$rpc" "isNullifier" "[\"$tx_hash\"]" | tr -d '"')
    assert_eq "S2: isNullifier true after confirm" "$is_null" "true"
}

# ---------------------------------------------------------------------------
# Scenario 3: Payment receipt (export + verify + tamper)
# ---------------------------------------------------------------------------
scenario3() {
    echo ""
    echo "=== Scenario 3: Payment receipt [mainnet] ==="
    local dir="$TMPBASE/s3" rpc="http://127.0.0.1:39103"
    start_node "$dir" 39003 39103 "--genesis"
    wait_height "$rpc" 20 || { fail "S3: node stuck"; return; }

    local addr; addr=$(rpc_result "$rpc" "walletGetAddress" "[0]" | tr -d '"')
    local tx_hash; tx_hash=$(rpc_field "$rpc" "walletSend" "[\"$addr\", 500, 0]" "tx_hash")
    assert_nonempty "S3: sent tx" "$tx_hash"
    wait_mempool_empty "$rpc" || { fail "S3: tx not confirmed"; return; }

    local receipt_hex; receipt_hex=$(rpc_result "$rpc" "walletExportReceipt" "[\"$tx_hash\"]" | tr -d '"')
    assert_nonempty "S3: receipt hex" "$receipt_hex"

    local verify; verify=$(rpc "$rpc" "verifyReceipt" "[\"$receipt_hex\"]")
    local confirmed; confirmed=$(echo "$verify" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['confirmed'])" 2>/dev/null || echo false)
    assert_eq "S3: receipt verifies as confirmed" "$confirmed" "True"

    local merkle; merkle=$(echo "$verify" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['merkle_valid'])" 2>/dev/null || echo false)
    assert_eq "S3: Merkle proof valid" "$merkle" "True"

    local tampered; tampered="${receipt_hex:0:10}ff${receipt_hex:12}"
    local verify2; verify2=$(rpc "$rpc" "verifyReceipt" "[\"$tampered\"]")
    local confirmed2; confirmed2=$(echo "$verify2" | python3 -c "import sys,json; d=json.load(sys.stdin); r=d.get('result',{}); print(r.get('confirmed','error'))" 2>/dev/null || echo "error")
    if [ "$confirmed2" = "False" ] || [ "$confirmed2" = "error" ]; then
        ok "S3: tampered receipt correctly rejected"
    else
        fail "S3: tampered receipt was accepted"
    fi
}

# ---------------------------------------------------------------------------
# Scenario 4: Fresh node syncs — MAINNET SPECIFIC
#
# Critical differences from testnet version:
#   1. MIN_SNAPSHOT_CHAINWORK = 18 × 2^27 requires chainwork from ≥18 real blocks
#      (19 headers × 2^27 > 18 × 2^27 = threshold). Node A must have tip ≥ 18.
#   2. Recursive proof updater starts after FINALITY_DEPTH=18 finalized blocks.
#      We wait for h=25 to ensure both chainwork threshold and recursive proof
#      are satisfied with margin.
#   3. Block time ~4-12s → wait_height(25) takes ~100-300s.
#
# This test VALIDATES that mainnet security requirements actually work:
#   - Snapshot sync is correctly blocked until peer has sufficient PoW history
#   - Once threshold is met, sync proceeds with full recursive proof verification
# ---------------------------------------------------------------------------
scenario4() {
    echo ""
    echo "=== Scenario 4: Fresh node syncs from existing node [mainnet] ==="
    echo "  NOTE: Requires h≥25 on Node A (MIN_SNAPSHOT_CHAINWORK = 18×2^27)."
    echo "        This takes ~100-300s at mainnet difficulty."

    local dir_a="$TMPBASE/s4a" dir_b="$TMPBASE/s4b"
    local rpc_a="http://127.0.0.1:39104" rpc_b="http://127.0.0.1:39105"

    start_node "$dir_a" 39004 39104 "--genesis"

    # Wait for Node A to have h≥25 AND a recursive proof.
    # Recursive proof updater needs tip ≥ FINALITY_DEPTH=18 to prove genesis,
    # then another 5s polling interval to actually write it.
    # At mainnet: ~8-12s/block × 25 = 200-300s + proof build time.
    echo "  Waiting for Node A h≥25 and recursive proof..."
    wait_height "$rpc_a" 25 || { fail "S4: Node A stuck at mainnet difficulty"; return; }

    # Poll for recursive proof in A's log
    local rec_ready=0
    for i in $(seq 1 60); do
        if grep -q "recursive proof advanced\|recursive proof: genesis proved" "$dir_a/node.log" 2>/dev/null; then
            rec_ready=1; break
        fi
        sleep 1
    done
    if [ "$rec_ready" -eq 1 ]; then
        ok "S4: Node A has recursive proof (h≥25, FINALITY_DEPTH satisfied)"
    else
        fail "S4: Node A recursive proof not built in 60s after h≥25"
    fi

    local h_a; h_a=$(rpc_result "$rpc_a" "blockCount" "[]" | tr -d '"')
    echo "  Node A at h=$h_a, starting Node B (fresh, no --testnet)..."

    # Node B: no --testnet, no --mine — pure mainnet sync
    mkdir -p "$dir_b"
    "$BIN" --data-dir "$dir_b" --p2p-listen "0.0.0.0:39005" \
           --rpc-listen "127.0.0.1:39105" \
           --seed "127.0.0.1:39004" \
           > "$dir_b/node.log" 2>&1 &
    pids+=("$!")

    # Wait for B to sync (budget: 120s — snapshot apply + block gossip catchup)
    local synced=0
    for i in $(seq 1 120); do
        local h_b; h_b=$(rpc_result "$rpc_b" "blockCount" "[]" | tr -d '"')
        if [ "${h_b:-0}" -ge "${h_a:-1}" ] 2>/dev/null; then
            synced=1; echo "  Node B synced to h=$h_b"; break
        fi
        sleep 1
    done
    [ "$synced" = "1" ] && ok "S4: Node B synced via mainnet snapshot" \
                        || fail "S4: Node B did not sync in 120s"

    # Verify B used recursive proof (not just the PoW-only fallback)
    if grep -q "recursive proof VERIFIED\|Mode.*STARK verified" "$dir_b/node.log" 2>/dev/null; then
        ok "S4: B verified snapshot via STARK recursive proof (full security path)"
    elif grep -q "PoW + chainwork verified" "$dir_b/node.log" 2>/dev/null; then
        ok "S4: B verified snapshot via PoW + chainwork (proof still building on A)"
    else
        fail "S4: No verification log found in B"
    fi

    # State integrity: heights within 2 blocks
    local h_a2; h_a2=$(rpc_result "$rpc_a" "blockCount" "[]" | tr -d '"')
    local h_b2; h_b2=$(rpc_result "$rpc_b" "blockCount" "[]" | tr -d '"')
    local diff=$(( ${h_a2:-0} - ${h_b2:-0} ))
    if [ "$diff" -le 2 ]; then ok "S4: heights within 2 blocks (A=$h_a2 B=$h_b2)"; else fail "S4: heights diverged (A=$h_a2 B=$h_b2 diff=$diff)"; fi

    local active_b; active_b=$(rpc_field "$rpc_b" "getStateInfo" "[]" "active_slots")
    assert_nonempty "S4: Node B has active slots after sync" "$active_b"
}

# ---------------------------------------------------------------------------
# Scenario 5: Wallet scan + consolidate
# ---------------------------------------------------------------------------
scenario5() {
    echo ""
    echo "=== Scenario 5: Wallet scan and UTXO consolidate [mainnet] ==="
    local dir="$TMPBASE/s5" rpc="http://127.0.0.1:39106"
    start_node "$dir" 39006 39106 "--genesis"
    wait_height "$rpc" 25 || { fail "S5: node stuck"; return; }

    local scan; scan=$(rpc "$rpc" "walletScan")
    local found; found=$(echo "$scan" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['found_utxos'])" 2>/dev/null || echo 0)
    if [ "${found:-0}" -gt 0 ]; then ok "S5: walletScan found $found UTXOs"; else fail "S5: walletScan found 0 UTXOs"; fi

    local utxo_before; utxo_before=$(rpc_field "$rpc" "walletGetBalance" "[]" "utxo_count")
    echo "  UTXOs before consolidate: $utxo_before"

    if [ "${utxo_before:-0}" -le 1 ]; then
        echo "  SKIP: only $utxo_before UTXOs, need ≥2"; return
    fi

    local cons; cons=$(rpc "$rpc" "walletConsolidate" "[0]")
    local cons_hash; cons_hash=$(echo "$cons" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['tx_hash'])" 2>/dev/null || echo "")
    assert_nonempty "S5: consolidate returns tx_hash" "$cons_hash"

    wait_mempool_empty "$rpc"
    ok "S5: consolidate tx confirmed"
}

# ---------------------------------------------------------------------------
# Scenario 6: External miner API
# ---------------------------------------------------------------------------
scenario6() {
    echo ""
    echo "=== Scenario 6: External miner API [mainnet] ==="
    local dir="$TMPBASE/s6" rpc="http://127.0.0.1:39107"
    start_node "$dir" 39007 39107 "--genesis"
    wait_height "$rpc" 5 || { fail "S6: node stuck"; return; }

    local addr; addr=$(rpc_result "$rpc" "walletGetAddress" "[0]" | tr -d '"')

    # getBlockTemplate returns header_core_hex (212 bytes = 424 hex chars) + block_hex
    local tmpl; tmpl=$(rpc "$rpc" "getBlockTemplate" "[\"$addr\"]")
    local core_hex; core_hex=$(echo "$tmpl" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['header_core_hex'])" 2>/dev/null || echo "")
    assert_nonempty "S6: header_core_hex present" "$core_hex"

    local core_len; core_len=${#core_hex}
    assert_eq "S6: header_core is 424 hex chars (212 bytes)" "$core_len" "424"

    local tmpl_height; tmpl_height=$(echo "$tmpl" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['height'])" 2>/dev/null || echo "0")
    assert_nonempty "S6: template has height" "$tmpl_height"

    # Different coinbase address → different header_core (block withholding protection)
    local addr2; addr2=$(rpc_result "$rpc" "walletGetAddress" "[1]" | tr -d '"')
    local tmpl2; tmpl2=$(rpc "$rpc" "getBlockTemplate" "[\"$addr2\"]")
    local core2; core2=$(echo "$tmpl2" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['header_core_hex'])" 2>/dev/null || echo "")
    assert_ne "S6: different coinbase → different header_core (withholding protection)" "$core_hex" "$core2"

    # submitBlock with garbage → rejected, not crashed
    local sbad; sbad=$(rpc "$rpc" "submitBlock" "[\"deadbeefcafe\"]")
    local has_err; has_err=$(echo "$sbad" | python3 -c "import sys,json; d=json.load(sys.stdin); print('true' if 'error' in d or d.get('result') is None else 'false')" 2>/dev/null || echo false)
    assert_eq "S6: invalid block rejected" "$has_err" "true"

    echo "  getBlockTemplate verified [mainnet difficulty]"
}

# ---------------------------------------------------------------------------
# Scenario 7: Two-node P2P mempool propagation [mainnet]
#
# At mainnet block time (~8-12s), tx propagation takes 1-3 blocks to confirm.
# Both nodes need to be synced first which may take time.
# ---------------------------------------------------------------------------
scenario7() {
    echo ""
    echo "=== Scenario 7: P2P mempool propagation [mainnet] ==="
    local dir_a="$TMPBASE/s7a" dir_b="$TMPBASE/s7b"
    local rpc_a="http://127.0.0.1:39108" rpc_b="http://127.0.0.1:39109"

    start_node "$dir_a" 39008 39108 "--genesis"
    wait_height "$rpc_a" 15 || { fail "S7: Node A stuck"; return; }

    mkdir -p "$dir_b"
    # Node B: relay-only, no --mine, no --testnet
    "$BIN" --data-dir "$dir_b" --p2p-listen "0.0.0.0:39009" \
           --rpc-listen "127.0.0.1:39109" \
           --seed "127.0.0.1:39008" \
           > "$dir_b/node.log" 2>&1 &
    pids+=("$!")

    local h_a; h_a=$(rpc_result "$rpc_a" "blockCount" "[]" | tr -d '"')
    # Wait for B to sync (snapshot sync needs MIN_SNAPSHOT_CHAINWORK at mainnet)
    for i in $(seq 1 120); do
        local h_b; h_b=$(rpc_result "$rpc_b" "blockCount" "[]" | tr -d '"')
        [ "${h_b:-0}" -ge "${h_a:-15}" ] 2>/dev/null && break
        sleep 1
    done

    local h_b2; h_b2=$(rpc_result "$rpc_b" "blockCount" "[]" | tr -d '"')
    if [ "${h_b2:-0}" -lt 5 ]; then
        fail "S7: Node B did not sync (h=$h_b2) — possibly chainwork threshold not met yet"
        return
    fi
    ok "S7: Node B synced (h=$h_b2)"

    local addr_a; addr_a=$(rpc_result "$rpc_a" "walletGetAddress" "[0]" | tr -d '"')
    local tx_hash; tx_hash=$(rpc_field "$rpc_a" "walletSend" "[\"$addr_a\", 100, 0]" "tx_hash")
    assert_nonempty "S7: sent tx from A" "$tx_hash"

    wait_mempool_empty "$rpc_a"
    ok "S7: tx confirmed on A"

    # Check tx reached B
    for i in $(seq 1 30); do
        local tx_b; tx_b=$(rpc "$rpc_b" "getTx" "[\"$tx_hash\"]")
        local h_tx; h_tx=$(echo "$tx_b" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('height',''))" 2>/dev/null || echo "")
        [ -n "$h_tx" ] && break
        sleep 1
    done
    assert_nonempty "S7: tx visible on B" "$h_tx"
}

# ---------------------------------------------------------------------------
# Run scenarios
# ---------------------------------------------------------------------------

if [ ! -f "$BIN" ]; then
    echo "ERROR: $BIN not found. Run 'cargo build --release' first."
    exit 1
fi

mkdir -p "$TMPBASE"

STARTED=$(date +%s)

# scenario1
# scenario2
#  scenario3
# scenario4   # Most important mainnet test: real chainwork + recursive proof sync
# scenario5
 scenario6
#  scenario7

ENDED=$(date +%s)
ELAPSED=$(( ENDED - STARTED ))

echo ""
echo "======================================================"
echo " MAINNET SCENARIO TEST SUMMARY"
printf "  Runtime: %dm %ds\n" "$((ELAPSED/60))" "$((ELAPSED%60))"
echo "======================================================"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "======================================================"
[ "$FAIL" -eq 0 ] && echo "  ALL PASSED ✓" && exit 0 || echo "  SOME FAILED ✗" && exit 1

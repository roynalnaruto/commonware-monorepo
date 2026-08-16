#!/usr/bin/env bash
#
# The whole rail, end to end, on one machine.
#
# Four validator processes and one client. The client hands a 256 KiB file to validator 0, watches
# it get batched, erasure-coded, attested by a quorum, certified, and finalized into a block, and
# then reads it back from validator 2 — a node that never saw the submission and holds one shard of
# the batch, so what comes back was reconstructed from custodians and verified against the
# certificate rather than handed over by the node that built it. The file that goes in and the file
# that comes out are compared byte for byte.
#
# Usage: examples/blob/demo.sh
# Exits 0 if the retrieved bytes are identical to the submitted bytes, 1 otherwise.

set -euo pipefail

# The deployment. Four validators is f = 1: a quorum of 3 attestations certifies a batch, and any
# 2 of the 4 shards reconstruct it.
VALIDATORS=(0 1 2 3)
BASE_PORT=3000
CLIENT_SEED=100
CLIENT_PORT=4000
GATEWAY=0            # the validator the client submits to
READER=2             # the validator it reads back from, deliberately not the gateway
BLOB_BYTES=$((256 * 1024))

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK=/tmp/commonware-blob
BIN="$ROOT/target/release/commonware-blob"

# How long to wait for each stage. The client does its own waiting for connectivity and for
# inclusion; these bound the stages the script is responsible for.
LISTEN_TIMEOUT=60    # seconds for a validator to bind its port
CONSENSUS_TIMEOUT=90 # seconds for every validator to reach MIN_VIEWS
MIN_VIEWS=20         # views every validator finalizes before anything is submitted

# Kill every validator we started, whichever way the script ends.
PIDS=()
cleanup() {
    for pid in "${PIDS[@]:-}"; do
        kill "$pid" 2>/dev/null || true
    done
    for pid in "${PIDS[@]:-}"; do
        wait "$pid" 2>/dev/null || true
    done
}
trap cleanup EXIT

# Waits until something is listening on a port, rather than sleeping and hoping.
wait_for_listener() {
    local port=$1 deadline=$((SECONDS + LISTEN_TIMEOUT))
    while ! (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do
        if ((SECONDS >= deadline)); then
            echo "FAIL: nothing listening on port $port after ${LISTEN_TIMEOUT}s" >&2
            return 1
        fi
        sleep 0.2
    done
}

# Waits until a validator has finalized MIN_VIEWS blocks.
#
# More than one, because the first few views are the ones where a node can still finalize a block
# whose payload it has not received yet: bare simplex carries payload digests and a separate gossip
# carries the payloads, and while peers are still connecting the second can lose a race with the
# first. Such a node never records that block's certificates, so reading a batch back from it would
# fail. The race is confined to the first half-second, and this is how the demo waits it out rather
# than sleeping through it. Finalizing at all is also what makes a validator's watermark real,
# which is what a batch's dispersal view is stamped from.
wait_for_consensus() {
    local seed=$1 log="$WORK/$seed/validator.log" deadline=$((SECONDS + CONSENSUS_TIMEOUT))
    local views
    while true; do
        # `grep -c` exits non-zero on no matches, which `set -e` would take for a failure.
        views=$(grep -c 'finalized' "$log" 2>/dev/null) || views=0
        if ((views >= MIN_VIEWS)); then
            return 0
        fi
        if ((SECONDS >= deadline)); then
            echo "FAIL: validator $seed finalized $views of $MIN_VIEWS views in ${CONSENSUS_TIMEOUT}s" >&2
            tail -n 20 "$log" >&2 || true
            return 1
        fi
        sleep 0.2
    done
}

echo "== building"
cargo build --release -p commonware-blob --manifest-path "$ROOT/Cargo.toml"

echo "== preparing $WORK"
rm -rf "$WORK"
mkdir -p "$WORK"
for seed in "${VALIDATORS[@]}"; do
    mkdir -p "$WORK/$seed"
done

# Every node derives every identity from the seed list, so the command lines below are the whole
# of the deployment's configuration. Validator 0 is the bootstrapper the others dial; it learns
# their addresses when they connect and gossips them onwards.
PARTICIPANTS=$(
    IFS=,
    echo "${VALIDATORS[*]}"
)
BOOTSTRAPPER=${VALIDATORS[0]}
BOOTSTRAPPER_PORT=$((BASE_PORT + BOOTSTRAPPER))
echo "== starting ${#VALIDATORS[@]} validators"
for seed in "${VALIDATORS[@]}"; do
    port=$((BASE_PORT + seed))
    args=(
        validator
        --me "$seed@$port"
        --participants "$PARTICIPANTS"
        --clients "$CLIENT_SEED"
        --storage-dir "$WORK/$seed"
    )
    if [ "$seed" != "$BOOTSTRAPPER" ]; then
        args+=(--bootstrappers "$BOOTSTRAPPER@127.0.0.1:$BOOTSTRAPPER_PORT")
    fi
    "$BIN" "${args[@]}" >"$WORK/$seed/validator.log" 2>&1 &
    pid=$!
    PIDS+=("$pid")
    echo "   validator $seed on port $port (pid $pid)"
done

echo "== waiting for the network to form"
for seed in "${VALIDATORS[@]}"; do
    wait_for_listener $((BASE_PORT + seed))
done
for seed in "${VALIDATORS[@]}"; do
    wait_for_consensus "$seed"
done
echo "   every validator is listening and has finalized $MIN_VIEWS views"

echo "== generating a $BLOB_BYTES byte blob"
head -c "$BLOB_BYTES" /dev/urandom >"$WORK/input.bin"

VALIDATOR_LIST=""
for seed in "${VALIDATORS[@]}"; do
    VALIDATOR_LIST+="${VALIDATOR_LIST:+,}$seed@127.0.0.1:$((BASE_PORT + seed))"
done

echo "== posting it"
set +e
"$BIN" client \
    --me "$CLIENT_SEED@$CLIENT_PORT" \
    --validators "$VALIDATOR_LIST" \
    post \
    --file "$WORK/input.bin" \
    --out "$WORK/output.bin" \
    --gateway "$GATEWAY" \
    --from "$READER"
posted=$?
set -e

echo "== comparing"
if ((posted != 0)); then
    echo "FAIL: the client exited $posted"
    exit 1
fi
if ! cmp -s "$WORK/input.bin" "$WORK/output.bin"; then
    echo "FAIL: retrieved bytes differ from what was submitted"
    exit 1
fi
echo "   $WORK/input.bin == $WORK/output.bin ($(wc -c <"$WORK/input.bin" | tr -d ' ') bytes)"
echo "PASS"

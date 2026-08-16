# commonware-blob

Post blobs to a ZODA-backed data-availability rail alongside a consensus chain.

Blob bytes never enter a block. A gateway -- any validator, chosen by the client -- batches the
blobs submitted to it, erasure-codes each batch with [ZODA](../../coding/README.md), and sends every
validator a single shard. Each validator checks its shard against the batch commitment, writes it to
durable custody, and returns a signed attestation. `2f + 1` of those attestations aggregate into one
availability certificate, and that certificate is the only blob-related object consensus ever
orders. Blocks stay a constant size no matter how much data is flowing, and the network carries one
shard per validator instead of one copy of the batch per validator.

What a certificate buys is a counting argument, not a promise: `2f + 1` signers minus at most `f`
faulty ones leaves `f + 1` honest custodians, and `f + 1` shards are exactly what reconstruction
needs. So a reader gathers shards from the certificate's *signers*, decodes, and re-derives
everything it was told. Claims here sit in three tiers, and the whole design falls out of keeping
them apart: **attested availability** (`2f + 1` validators, each having checked only its own shard),
**gateway-claimed structure** (the blob-tree root, signed by one gateway, outside the attested
subject -- a lie is attributable and provable, and can never fake availability), and
**reader-derived truth** (whatever a reader recomputes from the decoded bytes, trusting nobody).

Blob identities and the two Merkle trees over them are Poseidon2-BN254 with Noir-compatible
parameters, so a future execution layer could verify "this blob is at leaf `i` of that batch, and
these 4 KiB are at offset `o` of it" inside a circuit for a few dozen permutations. That is the
hash-native counterpart of EIP-4844's point evaluation, and the crate documentation
(`cargo doc --open -p commonware-blob`) works through what an execution layer on top of this would
look like.

## Quickstart

_To run this example, you must first install [Rust](https://www.rust-lang.org/tools/install)._

```bash
./demo.sh
```

Four validator processes and one client on localhost. The client hands a 256 KiB file to validator
0, waits for it to be batched, dispersed, attested, certified, and finalized, then reads it back
from validator 2 -- a node that never saw the submission and holds one shard of the batch, so what
comes back was reconstructed from custodians and verified against the certificate. It prints `PASS`
and exits 0 when the retrieved bytes are identical to the submitted bytes. Logs and both files are
left in `/tmp/commonware-blob`.

## Usage

Run from this directory. Every identity is derived from a seed, so the seed lists below are the
whole of the deployment's configuration; `--clients` is required because validators only accept
peers they were told about.

### Validator 0 (Bootstrapper)

```bash
cargo run --release -- validator --me 0@3000 --participants 0,1,2,3 --clients 100 --storage-dir /tmp/commonware-blob/0
```

### Validators 1 to 3

```bash
cargo run --release -- validator --me 1@3001 --participants 0,1,2,3 --clients 100 --bootstrappers 0@127.0.0.1:3000 --storage-dir /tmp/commonware-blob/1
cargo run --release -- validator --me 2@3002 --participants 0,1,2,3 --clients 100 --bootstrappers 0@127.0.0.1:3000 --storage-dir /tmp/commonware-blob/2
cargo run --release -- validator --me 3@3003 --participants 0,1,2,3 --clients 100 --bootstrappers 0@127.0.0.1:3000 --storage-dir /tmp/commonware-blob/3
```

### Client

`post` is submit, wait, and retrieve in one command, which is what the demo runs:

```bash
mkdir -p /tmp/commonware-blob
head -c 262144 /dev/urandom > /tmp/commonware-blob/input.bin
cargo run --release -- client --me 100@4000 --validators 0@127.0.0.1:3000,1@127.0.0.1:3001,2@127.0.0.1:3002,3@127.0.0.1:3003 post --file /tmp/commonware-blob/input.bin --out /tmp/commonware-blob/output.bin --gateway 0 --from 2
```

The same three steps separately, which is what a real client would do:

```bash
# Hand the file to a gateway. Prints the BlobId, which is derived from the bytes.
cargo run --release -- client --me 100@4000 --validators 0@127.0.0.1:3000,1@127.0.0.1:3001,2@127.0.0.1:3002,3@127.0.0.1:3003 submit --file /tmp/commonware-blob/input.bin --gateway 0

# Poll the gateway that took it. `--wait` blocks until it is included or abandoned, and an
# included blob prints the commitment of the batch that carries it.
cargo run --release -- client --me 100@4000 --validators 0@127.0.0.1:3000,1@127.0.0.1:3001,2@127.0.0.1:3002,3@127.0.0.1:3003 status --id <blob-id> --gateway 0 --wait

# Read it back from any validator, verifying the certificate, the commitment, and the claimed
# blob-tree root on the way.
cargo run --release -- client --me 100@4000 --validators 0@127.0.0.1:3000,1@127.0.0.1:3001,2@127.0.0.1:3002,3@127.0.0.1:3003 get --commitment <commitment> --id <blob-id> --out /tmp/commonware-blob/output.bin --from 2
```

Blobs are between 1 byte and 512 KiB; nothing is chunked, so splitting a larger file is the caller's
job.

### Retrieval and expiry

- **Any validator can serve a read.** A batch query is answered from the certificate registry plus
  a gather from custodians, and the client verifies the answer itself, so there is nothing to trust
  the responder about. Reading from a non-gateway is the interesting case, which is why the demo
  does it.
- **A status poll must go back to the accepting gateway.** Status is one node's bookkeeping about
  submissions it accepted, not chain state. Another validator answers "unknown".
- **Retrievability is bounded.** A shard is kept until `D + FRESHNESS + WINDOW`, where `D` is the
  view the batch was dispersed at, `FRESHNESS` is 32 views and `WINDOW` is 64 views. A blob included
  at view `H` is therefore retrievable for at least 64 more views. These are views rather than
  seconds on purpose, but for a sense of scale: this deployment on one machine finalizes a view
  roughly every 100 ms, so the window is on the order of ten seconds. Past it, a read fails cleanly
  as expired rather than returning anything wrong.
- **Nothing is backfilled.** A validator that is stopped and restarted resumes from what was
  durable, but one that is away long enough to miss a run of finalizations cannot be given what it
  missed.

## Testing

```bash
just test -p commonware-blob                # the whole suite
just test -p commonware-blob custody::      # one module, by path
just test -p commonware-blob e2e_           # the three end-to-end tests
```

Every test runs on the deterministic runtime, so a failure reproduces exactly. The two measurement
harnesses are ignored by default because they are measurements rather than assertions, and they need
release mode -- debug timings for field arithmetic mean nothing:

```bash
cargo test --release -p commonware-blob measure_poseidon2_sealing -- --ignored --nocapture
cargo test --release -p commonware-blob measure_zoda_attestation_path -- --ignored --nocapture
```

The first answers whether a batch can be sealed inside the batch timer; the second times the
`weaken` and `check` an attestor runs per dispersal and a reader runs per gathered shard.

### Poseidon2 conformance

`conformance/noir/` is the Noir side of the sponge in `src/poseidon2/`. It rebuilds
`Poseidon2Hasher::finish_ref` semantics on the public `std::hash::poseidon2_permutation` -- the only
Poseidon2 entry point the Noir standard library still exports -- and asserts the same vectors the
Rust tests embed, so the two implementations are checked against each other rather than assumed to
agree. It is not a cargo target; run it by hand when the sponge, the round constants, or the pinned
Noir version change:

```bash
cd conformance/noir
nargo test --show-output   # generated with nargo 1.0.0-beta.26
```

## Limitations

Deliberate boundaries of an example, each covered in more detail in the crate documentation:

- no payload backfill, so a node offline across a run of finalizations cannot catch up on what it
  missed;
- no proofs of custody: a validator that attests and then deletes its shard is undetectable until
  somebody tries to retrieve;
- no permanence across validator rotation, since shard `i` is bound to participant `i` of the
  current set;
- no inclusion guarantee and no fee market, so submissions are unpriced;
- `commonware-coding` is ALPHA: shard and commitment wire formats may change without a migration;
- retrieval returns a whole batch in one 16 MiB-capped message, with no streaming or range
  requests;
- status is served only by the gateway that accepted the blob;
- the client protocol has no correlation identifier, so a client sends one request at a time (a
  late reply costs a poll, never a wrong verdict);
- `demo.sh` pins ports 3000-3003 and 4000 and the directory `/tmp/commonware-blob`, with no
  collision detection.

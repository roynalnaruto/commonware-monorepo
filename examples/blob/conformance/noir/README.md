# Noir conformance vectors

`src/main.nr` is the Noir side of the Poseidon2 sponge in
[`src/poseidon2/sponge.rs`](../../src/poseidon2/sponge.rs). It rebuilds
`Poseidon2Hasher::finish_ref` semantics (capacity slot `len << 64`, rate-3 absorb, trailing
permutation) on top of the public `std::hash::poseidon2_permutation`, which is the only Poseidon2
entry point the Noir standard library still exports, and asserts every vector the Rust
conformance test `poseidon2::permutation::tests::noir_vectors` embeds.

This is not a cargo target and nothing in the Rust build depends on it. It is run by hand when the
sponge, the round constants, or the pinned Noir version change:

```bash
cd examples/blob/conformance/noir
nargo test --show-output   # generated with nargo 1.0.0-beta.26
```

The chain of trust the three tests establish, in order: the permutation matches barretenberg's
published test vector; the sponge built over it reproduces the digest `noir_stdlib`'s own
`finish_ref_matches_known_digest` asserts; and the nine input lengths the rail hashes produce the
values compiled into the Rust test.

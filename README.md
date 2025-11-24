# ZK Airdrop (Poseidon/Keccak/ECDSA)

This repo builds and proves a private airdrop circuit: a claimant proves they control an Ethereum secp256k1 key whose address is in a Merkle tree, without revealing the address or signature. The nullifier is `Poseidon(address)`, so each eligible address can claim exactly once. The Merkle root is immutable and comes from the prebuilt `merkle.db`/`merkleroot.txt`.

## Layout
- `circuits/airdrop.circom` – Groth16 circuit (Keccak(pubkey) → address, Poseidon(address) leaf, Merkle path, ECDSA on fixed msg `keccak256("zk-airdrop-claim")`, nullifier = `Poseidon(Poseidon(sig_r, sig_s), DROP_DOMAIN)`).
- `circuits/airdrop_js/` – generated WASM and witness calculator (ignored in git).
- `circuits/airdrop_final.zkey`, `circuits/airdrop_verification_key.json` – Groth16 proving/verifying keys.
- `circuits/vendor/` – Poseidon, Keccak, secp256k1 ECDSA gadgets.
- `rust/src/bin/` – utilities: build/check Merkle DB, read meta, deterministic signing, and non-zk simulators for the airdrop proof.
- `merkle.db`, `merkleroot.txt` – LMDB Merkle tree and root built from `shards/manifest.txt`.

## Prereqs
- Node.js 18+, `circom` v2, `snarkjs` (uses `powersOfTau28_hez_final_22.ptau` in repo root).
- Rust toolchain if you want the LMDB + simulator utilities.

## Build & setup
```bash
npm install
npm run build:circom    # regenerates r1cs/wasm/sym under circuits/
npm run setup:groth16   # produces circuits/airdrop_final.zkey + verification_key.json
```

## Rust utilities
```bash
# Build Merkle DB + root from shards/manifest.txt (writes merkle.db + merkleroot.txt)
cargo run --release --bin build_merkle_db

# Inspect LMDB metadata
cargo run --release --bin print_meta

# Spot-check a leaf hash in merkle.db
cargo run --release --bin check_merkle_leaf -- 0x...address
```

### Non-zk airdrop simulators (for debugging)
```bash
# Produce a JSON artifact with address/pubkey/signature/path/nullifier/root
cargo run --release --bin airdrop_prove_sim -- <privkey_hex> --recipient 0x... (optional)

# Verify that artifact
cargo run --release --bin airdrop_verify_sim -- --input data/airdrop_proof_sim.json
```

The actual Groth16 proof generation/verification uses the `circuits/airdrop_js/airdrop.wasm` and `circuits/airdrop_final.zkey` produced above, with public signals `{root, nullifier, recipient}`. Keep `root` equal to the immutable value in `merkleroot.txt`. Nullifier is always `Poseidon(address)` as hashed in `build_merkle_db.rs`.

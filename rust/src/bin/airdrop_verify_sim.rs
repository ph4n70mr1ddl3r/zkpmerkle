use std::fs::File;
use std::io::Read;
use std::str::FromStr;

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use clap::Parser;
use hex;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use k256::elliptic_curve::sec1::Coordinates;
use k256::EncodedPoint;
use light_poseidon::{Poseidon, PoseidonHasher};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Simulated verifier for the private airdrop: checks signature, address binding, Merkle path, and nullifier.
#[derive(Debug, Parser)]
#[command(name = "airdrop-verify-sim")]
#[command(about = "Verify a non-zk airdrop proof artifact")]
struct Args {
    /// Path to the JSON produced by airdrop-prove-sim.
    #[arg(long, default_value = "data/airdrop_proof_sim.json")]
    input: String,
}

#[derive(Deserialize)]
struct ProofSim {
    message: String,
    message_sha256: String,
    address: String,
    recipient: String,
    pubkey: PubKey,
    signature: Sig,
    leaf_index: u64,
    leaf_hash: String,
    nullifier: String,
    root: String,
    merkle_path: Vec<String>,
    merkle_pos: Vec<u8>,
}

#[derive(Deserialize)]
struct PubKey {
    x: String,
    y: String,
}

#[derive(Deserialize)]
struct Sig {
    r: String,
    s: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut file = File::open(&args.input)
        .with_context(|| format!("failed to open {}", args.input))?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    let proof: ProofSim = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", args.input))?;

    // Rebuild verifying key.
    let vk = pubkey_from_hex(&proof.pubkey.x, &proof.pubkey.y)?;

    // Check address derives from pubkey.
    let derived_addr = eth_address(&vk)?;
    ensure!(
        derived_addr.eq_ignore_ascii_case(&proof.address),
        "address mismatch: derived {derived_addr}, proof {}",
        proof.address
    );

    // Verify signature over SHA-256(message).
    let mut sha = Sha256::new();
    sha.update(proof.message.as_bytes());
    let msg_digest = sha.finalize();
    ensure!(
        hex::encode(msg_digest) == proof.message_sha256,
        "message digest mismatch"
    );
    let sig = signature_from_hex(&proof.signature.r, &proof.signature.s)?;
    vk.verify_prehash(&msg_digest, &sig)
        .map_err(|e| anyhow!("signature verification failed: {e}"))?;

    // Recompute leaf/hash/nullifier.
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let leaf = hash_address(&proof.address, &mut poseidon, Fr::zero())?;
    ensure!(
        leaf.into_bigint().to_string() == proof.leaf_hash,
        "leaf hash mismatch"
    );

    let nullifier = poseidon_address(&proof.address)?;
    ensure!(
        nullifier.into_bigint().to_string() == proof.nullifier,
        "nullifier mismatch"
    );

    // Verify Merkle path to root.
    let root = fr_from_dec(&proof.root)?;
    let path: Vec<Fr> = proof
        .merkle_path
        .iter()
        .map(|s| fr_from_dec(s))
        .collect::<Result<_>>()?;
    ensure!(
        path.len() == proof.merkle_pos.len(),
        "path length mismatch"
    );
    let computed_root = recompute_root(&leaf, &path, &proof.merkle_pos)?;
    ensure!(
        computed_root == root,
        "computed root does not match provided root"
    );

    println!("Verification succeeded.");
    println!("root: {}", proof.root);
    println!("nullifier: {}", proof.nullifier);
    println!("recipient: {}", proof.recipient);
    Ok(())
}

fn pubkey_from_hex(x_hex: &str, y_hex: &str) -> Result<VerifyingKey> {
    let x_bytes = hex::decode(x_hex).context("invalid pubkey x hex")?;
    let y_bytes = hex::decode(y_hex).context("invalid pubkey y hex")?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        bail!("pubkey limbs must be 32 bytes each");
    }
    let x_arr: [u8; 32] = x_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey x must be 32 bytes"))?;
    let y_arr: [u8; 32] = y_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("pubkey y must be 32 bytes"))?;
    let point = EncodedPoint::from_affine_coordinates(&x_arr.into(), &y_arr.into(), false);
    VerifyingKey::from_encoded_point(&point)
        .map_err(|e| anyhow!("invalid pubkey: {e}"))
}

fn signature_from_hex(r_hex: &str, s_hex: &str) -> Result<Signature> {
    let r = hex::decode(r_hex).context("invalid r hex")?;
    let s = hex::decode(s_hex).context("invalid s hex")?;
    if r.len() != 32 || s.len() != 32 {
        bail!("signature limbs must be 32 bytes each");
    }
    let mut bytes = [0u8; 64];
    bytes[..32].copy_from_slice(&r);
    bytes[32..].copy_from_slice(&s);
    Signature::from_slice(&bytes).map_err(|e| anyhow!("invalid signature: {e}"))
}

fn eth_address(vk: &VerifyingKey) -> Result<String> {
    let point = vk.to_encoded_point(false);
    let coords = point.coordinates();
    let (x, y) = match coords {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => bail!("unexpected point encoding"),
    };
    let mut encoded = Vec::with_capacity(64);
    encoded.extend_from_slice(x);
    encoded.extend_from_slice(y);
    let mut hasher = Keccak256::new();
    hasher.update(&encoded);
    let out = hasher.finalize();
    let addr = &out[12..];
    Ok(format!("0x{}", hex::encode(addr)))
}

fn hash_address(address_hex: &str, poseidon: &mut Poseidon<Fr>, zero_leaf: Fr) -> Result<Fr> {
    let addr = address_hex.trim_start_matches("0x");
    let bytes = hex::decode(addr).with_context(|| format!("invalid hex address: {address_hex}"))?;
    if bytes.len() != 20 {
        bail!("address {} must be 20 bytes", address_hex);
    }
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(&bytes);
    let leaf_scalar = Fr::from_be_bytes_mod_order(&padded);
    if leaf_scalar.is_zero() {
        Ok(zero_leaf)
    } else {
        poseidon
            .hash(&[leaf_scalar, Fr::zero()])
            .map_err(|e| anyhow!(e.to_string()))
    }
}

fn poseidon_address(address: &str) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    hash_address(address, &mut poseidon, Fr::zero())
}

fn fr_from_dec(s: &str) -> Result<Fr> {
    Fr::from_str(s).map_err(|_| anyhow!("invalid field element: {s}"))
}

fn recompute_root(leaf: &Fr, path: &[Fr], pos: &[u8]) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let mut current = *leaf;
    for (sib, dir) in path.iter().zip(pos.iter()) {
        current = if *dir == 0 {
            poseidon
                .hash(&[current, *sib])
                .map_err(|e| anyhow!(e.to_string()))?
        } else {
            poseidon
                .hash(&[*sib, current])
                .map_err(|e| anyhow!(e.to_string()))?
        };
    }
    Ok(current)
}

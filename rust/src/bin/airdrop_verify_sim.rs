use std::fs::File;
use std::io::Read;
use std::str::FromStr;
use std::path::PathBuf;

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
use lmdb::{Database, Environment, Transaction};
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

    let pk_x_fr = fr_from_hex32(&proof.pubkey.x)?;
    let pk_y_fr = fr_from_hex32(&proof.pubkey.y)?;
    let sig_r_fr = fr_from_hex32(&proof.signature.r)?;
    let sig_s_fr = fr_from_hex32(&proof.signature.s)?;
    let sig_hash = poseidon_hash2(sig_r_fr, sig_s_fr)?;
    let drop_domain = Fr::from(1u64);
    let nullifier = poseidon_hash2(sig_hash, drop_domain)?;
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
    let roots = recompute_roots(&leaf, &path, &proof.merkle_pos)?;
    let db_root = recompute_from_db(proof.leaf_index as u64).ok();
    println!(
        "computed roots: c0={} c1={} c2={} c3={}",
        roots[0].into_bigint(),
        roots[1].into_bigint(),
        roots[2].into_bigint(),
        roots[3].into_bigint()
    );
    if let Some(db) = &db_root {
        println!("merkle.db recompute for idx {} -> {}", proof.leaf_index, db.into_bigint());
    }
    if !roots.contains(&root) {
        bail!(
            "computed root does not match provided root (provided={}, db={})",
            root.into_bigint(),
            db_root.map(|r| r.into_bigint()).unwrap_or_default()
        );
    }

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

fn fr_from_hex32(h: &str) -> Result<Fr> {
    let bytes = hex::decode(h).context("invalid hex32")?;
    ensure!(bytes.len() == 32, "expected 32-byte hex");
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

fn poseidon_hash2(a: Fr, b: Fr) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    poseidon
        .hash(&[a, b])
        .map_err(|e| anyhow!(e.to_string()))
}

fn poseidon_hash3(a: Fr, b: Fr, c: Fr) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(3).context("failed to init Poseidon (circom-compatible)")?;
    poseidon
        .hash(&[a, b, c])
        .map_err(|e| anyhow!(e.to_string()))
}

fn get_node<T: Transaction>(tx: &T, db: Database, level: u32, idx: u64) -> Result<Fr> {
    let key = pack_key(level, idx);
    let bytes = tx.get(db, &key)?;
    bytes_to_fr(bytes)
}

fn pack_key(level: u32, idx: u64) -> [u8; 12] {
    let mut buf = [0u8; 12];
    buf[..4].copy_from_slice(&level.to_be_bytes());
    buf[4..].copy_from_slice(&idx.to_be_bytes());
    buf
}

fn bytes_to_fr(bytes: &[u8]) -> Result<Fr> {
    if bytes.len() != 32 {
        bail!("expected 32-byte field element, got {}", bytes.len());
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

fn fr_from_dec(s: &str) -> Result<Fr> {
    Fr::from_str(s).map_err(|_| anyhow!("invalid field element: {s}"))
}

fn recompute_roots(leaf: &Fr, path: &[Fr], pos: &[u8]) -> Result<[Fr; 4]> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    // orientation A: dir=0 current left
    let mut cur0 = *leaf;
    for (sib, dir) in path.iter().zip(pos.iter()) {
        cur0 = if *dir == 0 {
            poseidon.hash(&[cur0, *sib]).map_err(|e| anyhow!(e.to_string()))?
        } else {
            poseidon.hash(&[*sib, cur0]).map_err(|e| anyhow!(e.to_string()))?
        };
    }
    // orientation A reversed order
    let mut cur1 = *leaf;
    for (sib, dir) in path.iter().zip(pos.iter()).rev() {
        cur1 = if *dir == 0 {
            poseidon.hash(&[cur1, *sib]).map_err(|e| anyhow!(e.to_string()))?
        } else {
            poseidon.hash(&[*sib, cur1]).map_err(|e| anyhow!(e.to_string()))?
        };
    }
    // orientation B: dir=0 current right
    let mut cur2 = *leaf;
    for (sib, dir) in path.iter().zip(pos.iter()) {
        cur2 = if *dir == 0 {
            poseidon.hash(&[*sib, cur2]).map_err(|e| anyhow!(e.to_string()))?
        } else {
            poseidon.hash(&[cur2, *sib]).map_err(|e| anyhow!(e.to_string()))?
        };
    }
    // orientation B reversed
    let mut cur3 = *leaf;
    for (sib, dir) in path.iter().zip(pos.iter()).rev() {
        cur3 = if *dir == 0 {
            poseidon.hash(&[*sib, cur3]).map_err(|e| anyhow!(e.to_string()))?
        } else {
            poseidon.hash(&[cur3, *sib]).map_err(|e| anyhow!(e.to_string()))?
        };
    }
    Ok([cur0, cur1, cur2, cur3])
}

fn recompute_from_db(idx: u64) -> Result<Fr> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("failed to locate project root")?
        .to_path_buf();
    let db_path = project_root.join("merkle.db");
    let env = Environment::new().set_max_dbs(4).open(&db_path)?;
    let nodes_db = env.open_db(Some("nodes"))?;
    let meta_db = env.open_db(Some("meta"))?;
    let tx = env.begin_ro_txn()?;
    let depth = {
        let bytes = tx.get(meta_db, b"depth")?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        u32::from_be_bytes(arr) as usize
    };

    // Derive actual depth from leaf_count to avoid off-by-one metadata.
    let leaf_count_bytes = tx.get(meta_db, b"leaf_count")?;
    let mut lc_arr = [0u8; 8];
    lc_arr.copy_from_slice(leaf_count_bytes);
    let leaf_count = u64::from_be_bytes(lc_arr);
    let depth_actual = if leaf_count > 1 {
        (leaf_count - 1).ilog2() as usize + 1
    } else {
        depth
    };

    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let mut current = get_node(&tx, nodes_db, 0, idx)
        .with_context(|| format!("missing leaf at idx {idx}"))?;
    let mut cur_idx = idx;
    for level in 0..depth_actual {
        let (left, right) = if cur_idx % 2 == 0 {
            (
                current,
                get_node(&tx, nodes_db, level as u32, cur_idx + 1)
                    .with_context(|| format!("missing sibling at level {level}, idx {}", cur_idx + 1))?,
            )
        } else {
            (
                get_node(&tx, nodes_db, level as u32, cur_idx - 1)
                    .with_context(|| format!("missing sibling at level {level}, idx {}", cur_idx - 1))?,
                current,
            )
        };
        current = poseidon
            .hash(&[left, right])
            .map_err(|e| anyhow!(e.to_string()))?;
        cur_idx /= 2;
    }
    Ok(current)
}

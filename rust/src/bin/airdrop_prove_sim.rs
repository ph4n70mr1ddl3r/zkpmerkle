use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use clap::Parser;
use hex;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::Coordinates;
use light_poseidon::{Poseidon, PoseidonHasher};
use lmdb::{Database, Environment, Transaction};
use serde::Serialize;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Simulated prover for the private airdrop: derives address, leaf, nullifier and Merkle path.
#[derive(Debug, Parser)]
#[command(name = "airdrop-prove-sim")]
#[command(about = "Generate a non-zk proof artifact for an address in merkle.db")]
struct Args {
    /// 32-byte hex private key (0x-prefixed or not).
    privkey: String,
    /// Message to sign (hashed with SHA-256).
    #[arg(long, default_value = "zk-airdrop-claim")]
    message: String,
    /// Optional recipient address (0x-prefixed). Defaults to the signer address.
    #[arg(long)]
    recipient: Option<String>,
    /// Path to the shard manifest (one filename per line).
    #[arg(long, default_value = "shards/manifest.txt")]
    manifest: PathBuf,
    /// Path to the LMDB directory.
    #[arg(long, default_value = "merkle.db")]
    db: PathBuf,
    /// Output JSON path.
    #[arg(long, default_value = "data/airdrop_proof_sim.json")]
    output: PathBuf,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
struct PubKey {
    x: String,
    y: String,
}

#[derive(Serialize)]
struct Sig {
    r: String,
    s: String,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let project_root = project_root()?;

    let manifest_path = project_root.join(&args.manifest);
    let db_path = project_root.join(&args.db);
    let output_path = project_root.join(&args.output);

    let sk = parse_privkey(&args.privkey)?;
    let vk = VerifyingKey::from(&sk);
    let (pk_x_hex, pk_y_hex) = pubkey_hex(&vk)?;
    let address = eth_address(&vk)?;
    let recipient = args.recipient.clone().unwrap_or_else(|| address.clone());

    let mut sha = Sha256::new();
    sha.update(args.message.as_bytes());
    let msg_digest = sha.finalize();

    let sig: Signature = sk.sign_prehash(&msg_digest).map_err(|e| anyhow!(e))?;
    let sig_r_hex = hex::encode(sig.r().to_bytes());
    let sig_s_hex = hex::encode(sig.s().to_bytes());

    let shard_files = read_manifest(&manifest_path)?;
    let leaf_index = find_address_index(&shard_files, &address)
        .with_context(|| format!("address {address} not found in shards"))?;

    let env = Environment::new()
        .set_max_dbs(4)
        .open(&db_path)
        .with_context(|| format!("failed to open lmdb env at {}", db_path.display()))?;
    let nodes_db = env
        .open_db(Some("nodes"))
        .context("failed to open nodes db")?;
    let meta_db = env.open_db(Some("meta")).context("failed to open meta db")?;

    let (leaf_hash, root, merkle_path, merkle_pos) =
        build_membership(&env, nodes_db, meta_db, leaf_index)?;
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let computed_leaf = hash_address(&address, &mut poseidon, Fr::zero())?;
    ensure!(
        computed_leaf == leaf_hash,
        "stored leaf does not match Poseidon(address)"
    );
    let pk_x_fr = fr_from_hex32(&pk_x_hex)?;
    let pk_y_fr = fr_from_hex32(&pk_y_hex)?;
    let sig_r_fr = fr_from_hex32(&sig_r_hex)?;
    let sig_s_fr = fr_from_hex32(&sig_s_hex)?;

    // Nullifier = Poseidon(pk_x, pk_y, Poseidon(sig_r, sig_s))
    let sig_hash = poseidon_hash2(sig_r_fr, sig_s_fr)?;
    let nullifier = poseidon_hash3(pk_x_fr, pk_y_fr, sig_hash)?;

    let proof = ProofSim {
        message: args.message,
        message_sha256: hex::encode(msg_digest),
        address: address.clone(),
        recipient,
        pubkey: PubKey {
            x: pk_x_hex,
            y: pk_y_hex,
        },
        signature: Sig {
            r: sig_r_hex,
            s: sig_s_hex,
        },
        leaf_index: leaf_index as u64,
        leaf_hash: leaf_hash.into_bigint().to_string(),
        nullifier: nullifier.into_bigint().to_string(),
        root: root.into_bigint().to_string(),
        merkle_path: merkle_path
            .into_iter()
            .map(|h| h.into_bigint().to_string())
            .collect(),
        merkle_pos,
    };

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create dir {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&proof)?;
    fs::write(&output_path, json)
        .with_context(|| format!("failed to write {}", output_path.display()))?;
    println!("Wrote {}", output_path.display());
    Ok(())
}

fn project_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("failed to locate project root")
}

fn parse_privkey(hex_key: &str) -> Result<SigningKey> {
    let trimmed = hex_key.strip_prefix("0x").unwrap_or(hex_key);
    if trimmed.len() != 64 {
        bail!("private key must be 32-byte hex (64 chars), got {}", trimmed.len());
    }
    let bytes = hex::decode(trimmed).context("invalid hex private key")?;
    let raw: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("private key must be exactly 32 bytes"))?;
    SigningKey::from_bytes(&raw.into()).map_err(|e| anyhow!("invalid secret key: {e}"))
}

fn pubkey_hex(vk: &VerifyingKey) -> Result<(String, String)> {
    let point = vk.to_encoded_point(false);
    let coords = point.coordinates();
    let (x, y) = match coords {
        Coordinates::Uncompressed { x, y } => (x, y),
        _ => bail!("unexpected point encoding"),
    };
    Ok((hex::encode(x), hex::encode(y)))
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
    let addr = &out[12..]; // last 20 bytes
    Ok(format!("0x{}", hex::encode(addr)))
}

fn read_manifest(path: &Path) -> Result<Vec<PathBuf>> {
    let file = File::open(path).with_context(|| format!("failed to open manifest {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        entries.push(path.parent().unwrap_or_else(|| Path::new("")).join(trimmed));
    }
    if entries.is_empty() {
        bail!("manifest {} is empty", path.display());
    }
    Ok(entries)
}

fn find_address_index(shard_files: &[PathBuf], target: &str) -> Result<usize> {
    let target = target.trim();
    let mut total = 0usize;
    for shard in shard_files {
        let file = File::open(shard)
            .with_context(|| format!("failed to open shard file {}", shard.display()))?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.eq_ignore_ascii_case(target) {
                return Ok(total);
            }
            total += 1;
        }
    }
    Err(anyhow!("address not found"))
}

fn build_membership(
    env: &Environment,
    nodes_db: Database,
    meta_db: Database,
    leaf_index: usize,
) -> Result<(Fr, Fr, Vec<Fr>, Vec<u8>)> {
    let read_tx = env.begin_ro_txn()?;
    let (depth_meta, leaf_count) = {
        let bytes = read_tx.get(meta_db, b"depth")?;
        let mut arr = [0u8; 4];
        arr.copy_from_slice(bytes);
        let depth_meta = u32::from_be_bytes(arr) as usize;
        let lc_bytes = read_tx.get(meta_db, b"leaf_count")?;
        let mut lc_arr = [0u8; 8];
        lc_arr.copy_from_slice(lc_bytes);
        let lc = u64::from_be_bytes(lc_arr);
        (depth_meta, lc as usize)
    };
    // Use leaf_count to derive actual depth (power-of-two trees store root at log2(leaf_count) levels).
    let depth = if leaf_count > 1 {
        (leaf_count - 1).ilog2() as usize + 1
    } else {
        depth_meta
    };

    let root = {
        let bytes = read_tx.get(meta_db, b"root")?;
        bytes_to_fr(bytes)?
    };

    let leaf = get_node(&read_tx, nodes_db, 0, leaf_index as u64)
        .with_context(|| format!("missing leaf at idx {leaf_index}"))?;

    let mut path = Vec::with_capacity(depth);
    let mut pos = Vec::with_capacity(depth);
    let mut idx = leaf_index as u64;
    for level in 0..depth {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        let sibling = get_node(&read_tx, nodes_db, level as u32, sibling_idx)
            .with_context(|| format!("missing sibling at level {level}, idx {sibling_idx}"))?;
        path.push(sibling);
        pos.push(if idx % 2 == 0 { 0 } else { 1 });
        idx /= 2;
    }

    Ok((leaf, root, path, pos))
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

fn poseidon_address(address: &str) -> Result<Fr> {
    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    hash_address(address, &mut poseidon, Fr::zero())
}

fn fr_from_hex32(h: &str) -> Result<Fr> {
    let bytes = hex::decode(h).context("invalid hex")?;
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

fn bytes_to_fr(bytes: &[u8]) -> Result<Fr> {
    if bytes.len() != 32 {
        bail!("expected 32-byte field element, got {}", bytes.len());
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

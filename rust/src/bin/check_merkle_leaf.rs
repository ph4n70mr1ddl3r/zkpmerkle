use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::Fr;
use ark_ff::{PrimeField, Zero};
use clap::Parser;
use hex;
use light_poseidon::{Poseidon, PoseidonHasher};
use lmdb::{Database, Environment, Transaction};

/// Look up a specific address in merkle.db and verify its leaf hash.
#[derive(Debug, Parser)]
#[command(name = "check-merkle-leaf")]
#[command(about = "Verify a single leaf stored in merkle.db")]
struct Args {
    /// Address to check (0x-prefixed, 20 bytes).
    address: String,
    /// Path to the shard manifest (one filename per line).
    #[arg(long, default_value = "shards/manifest.txt")]
    manifest: PathBuf,
    /// Path to the existing LMDB directory.
    #[arg(long, default_value = "merkle.db")]
    db: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let project_root = project_root()?;

    let manifest_path = project_root.join(&args.manifest);
    let db_path = project_root.join(&args.db);

    let shard_files = read_manifest(&manifest_path)?;
    let target_addr = args.address.trim();
    let idx = find_address_index(&shard_files, target_addr)
        .with_context(|| format!("address {target_addr} not found in shards"))?;

    let mut poseidon =
        Poseidon::<Fr>::new_circom(2).context("failed to init Poseidon (circom-compatible)")?;
    let zero_leaf = Fr::zero();
    let expected = hash_leaf(target_addr, &mut poseidon, zero_leaf)?;

    let env = Environment::new()
        .set_max_dbs(4)
        .open(&db_path)
        .with_context(|| format!("failed to open lmdb env at {}", db_path.display()))?;
    let nodes_db = env
        .open_db(Some("nodes"))
        .context("failed to open nodes db")?;

    let read_tx = env.begin_ro_txn()?;
    let stored = get_node(&read_tx, nodes_db, 0, idx as u64)
        .with_context(|| format!("missing leaf at idx {idx}"))?;

    println!("Address: {target_addr}");
    println!("Leaf index: {idx}");
    println!("Expected leaf hash: {}", expected.into_bigint());
    println!("Stored leaf hash:   {}", stored.into_bigint());
    if expected == stored {
        println!("OK: stored hash matches Poseidon(address || 0).");
        Ok(())
    } else {
        bail!("mismatch: stored leaf hash does not match recomputed hash");
    }
}

fn project_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("failed to locate project root")
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

fn hash_leaf(address_hex: &str, poseidon: &mut Poseidon<Fr>, zero_leaf: Fr) -> Result<Fr> {
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
        hash_pair(poseidon, leaf_scalar, Fr::zero())
    }
}

fn hash_pair(poseidon: &mut Poseidon<Fr>, left: Fr, right: Fr) -> Result<Fr> {
    poseidon
        .hash(&[left, right])
        .map_err(|e| anyhow!(e.to_string()))
}

fn bytes_to_fr(bytes: &[u8]) -> Result<Fr> {
    ensure!(
        bytes.len() == 32,
        "expected 32-byte field element, got {}",
        bytes.len()
    );
    let mut buf = [0u8; 32];
    buf.copy_from_slice(bytes);
    Ok(Fr::from_be_bytes_mod_order(&buf))
}

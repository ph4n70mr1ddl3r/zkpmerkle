use std::path::PathBuf;

use anyhow::Context;
use ark_ff::PrimeField;
use lmdb::{Environment, Transaction};

fn main() -> anyhow::Result<()> {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("failed to locate project root")?
        .to_path_buf();
    let db_path = project_root.join("merkle.db");
    let env = Environment::new()
        .set_max_dbs(4)
        .open(&db_path)
        .with_context(|| format!("failed to open lmdb at {}", db_path.display()))?;
    let meta_db = env.open_db(Some("meta"))?;
    let tx = env.begin_ro_txn()?;
    let leaf_count = tx.get(meta_db, b"leaf_count")?;
    let depth = tx.get(meta_db, b"depth")?;
    let root = tx.get(meta_db, b"root")?;
    println!("leaf_count: {}", u64::from_be_bytes(leaf_count.try_into()?));
    println!("depth: {}", u32::from_be_bytes(depth.try_into()?));
    println!(
        "root: {}",
        ark_bn254::Fr::from_be_bytes_mod_order(root).into_bigint()
    );
    Ok(())
}

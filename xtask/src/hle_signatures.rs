//! `cargo xtask hle-signatures`: the signatures of the guest functions HLE
//! replaces, from a macOS build's dyld shared cache (phase 0's reader,
//! `symbolize::code`). For each routine it looks up the symbols that may
//! name it, takes each function from its address to the next function
//! start (less the padding after its last word), its first `ret` as its
//! exit, and runs the engine's own `Signature::of`, so a function the
//! engine would refuse is refused here with the same reason.
//!
//! It prints one report row per symbol found, `symbol image address length
//! exit verdict`. With `--out` it writes a `signatures.rs` table of the
//! eligible ones: routine, length, exit and hashes only, never bytes, one
//! `Signature::generated` line each under a comment naming the symbol,
//! image and build. With `--extract` it writes each function's bytes
//! (`<symbol>.bin`) and description (`<symbol>.json`), for the opt-in
//! real-bytes oracle (`tests/hle_real.rs`): Apple's bytes, which never go
//! in the repository, so `--extract` refuses a directory inside it.
use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use stela_engine::hle::{Id, Ineligible, Signature};

use crate::symbolize::code::{self, Function};

/// The longest function a signature covers: one fetch page.
const LIMIT: usize = 4096;
/// `ret`.
const RET: u32 = 0xd65f_03c0;
/// The words that pad a function to the next one's alignment, which it
/// never runs: UDF #0 and NOP.
const PADDING: [u32; 2] = [0, 0xd503_201f];

/// The symbols that may name each routine, to be confirmed by the report
/// on each macOS build.
///
/// Mach-O prepends a leading underscore to C symbols, so Libplatform's
/// `_platform_*` symbols appear in the shared cache as `__platform_*`.
pub const CANDIDATES: [(Id, &[&str]); 5] = [
    (
        Id::Memmove,
        &[
            "__platform_memmove",
            "__platform_memcpy",
            "_platform_memmove",
            "_memmove",
            "_memcpy",
            "_platform_memcpy",
        ],
    ),
    (
        Id::Bzero,
        &["__platform_bzero", "_platform_bzero", "_bzero", "___bzero"],
    ),
    (
        Id::Memset,
        &["__platform_memset", "_platform_memset", "_memset"],
    ),
    (
        Id::Memcmp,
        &[
            "__platform_memcmp",
            "__platform_bcmp",
            "_platform_memcmp",
            "_platform_bcmp",
            "_memcmp",
            "_bcmp",
        ],
    ),
    (
        Id::Strlen,
        &["__platform_strlen", "_platform_strlen", "_strlen"],
    ),
];

#[derive(Args)]
pub struct HleSignatures {
    /// The guest's dyld shared cache: its main file
    /// (`dyld_shared_cache_arm64e`, its subcaches beside it) or the
    /// directory holding it.
    #[arg(long)]
    cache: PathBuf,
    /// Write the eligible functions' signatures here as a `signatures.rs`
    /// table (`crates/stela-engine/src/hle/signatures.rs` once the oracle
    /// passes; a private path before).
    #[arg(long)]
    out: Option<PathBuf>,
    /// Write each function's bytes and description into this directory,
    /// outside the repository.
    #[arg(long)]
    extract: Option<PathBuf>,
    /// The macOS build the cache is from, such as `26B123`, for the table's
    /// comments.
    #[arg(long, default_value = "unknown-build")]
    build: String,
}

impl HleSignatures {
    pub fn run(&self) -> Result<()> {
        if let Some(extract) = &self.extract {
            refuse_inside_repository(extract)?;
        }
        let names: Vec<&str> = CANDIDATES
            .iter()
            .flat_map(|(_, names)| names.iter().copied())
            .collect();
        let functions = code::cache_functions(&self.cache, &names, LIMIT)?;
        ensure!(
            !functions.is_empty(),
            "{} names none of {names:?}",
            self.cache.display()
        );
        let mut rows = Vec::new();
        for function in &functions {
            let Some(id) = routine(&function.symbol) else {
                continue;
            };
            rows.push(Row::of(id, function));
        }
        println!("symbol image address length exit verdict");
        for row in &rows {
            println!("{}", row.report());
        }
        let eligible: Vec<&Row> = rows.iter().filter(|row| row.signature.is_some()).collect();
        println!(
            "{} of {} functions eligible; routines: {}",
            eligible.len(),
            rows.len(),
            CANDIDATES
                .iter()
                .map(|(id, _)| format!(
                    "{}={}",
                    id.name(),
                    eligible.iter().filter(|row| row.id == *id).count()
                ))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if let Some(out) = &self.out {
            std::fs::write(out, table(&eligible, &self.build))
                .with_context(|| format!("write {}", out.display()))?;
            println!("wrote {} signatures to {}", eligible.len(), out.display());
        }
        if let Some(extract) = &self.extract {
            std::fs::create_dir_all(extract)?;
            for (row, function) in rows
                .iter()
                .zip(functions.iter().filter(|f| routine(&f.symbol).is_some()))
            {
                let stem = format!("{}-{:x}", row.symbol.trim_start_matches('_'), row.address);
                std::fs::write(
                    extract.join(format!("{stem}.bin")),
                    &function.bytes[..row.length],
                )?;
                let description = serde_json::json!({
                    "id": row.id.name(),
                    "symbol": row.symbol,
                    "image": row.image,
                    "address": row.address,
                    "length": row.length,
                    "exit": row.exit,
                    "verdict": row.verdict,
                });
                std::fs::write(
                    extract.join(format!("{stem}.json")),
                    serde_json::to_string_pretty(&description)?,
                )?;
            }
            println!(
                "extracted {} functions to {}",
                rows.len(),
                extract.display()
            );
        }
        Ok(())
    }
}

/// The routine a symbol may name.
fn routine(symbol: &str) -> Option<Id> {
    CANDIDATES
        .iter()
        .find(|(_, names)| names.contains(&symbol))
        .map(|(id, _)| *id)
}

/// Refuse to write Apple's bytes into the repository.
fn refuse_inside_repository(path: &Path) -> Result<()> {
    let root = crate::tools::root();
    let absolute = std::path::absolute(path)?;
    if absolute.starts_with(root) {
        bail!(
            "--extract {} is inside the repository ({}): Apple's bytes stay outside it",
            path.display(),
            root.display()
        );
    }
    Ok(())
}

/// One function's report row and, if eligible, its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Row {
    id: Id,
    symbol: String,
    image: String,
    address: u64,
    /// Its bytes, its trailing padding left out.
    length: usize,
    exit: Option<u16>,
    verdict: String,
    signature: Option<Signature>,
}

impl Row {
    fn of(id: Id, function: &Function) -> Self {
        let bytes = trimmed(&function.bytes);
        let exit = first_ret(bytes);
        let page_offset = (function.address & 0xfff) as usize;
        let (signature, verdict) = if page_offset + bytes.len() > LIMIT {
            (None, String::from("crosses-page"))
        } else {
            match exit.map(|exit| Signature::of(id, bytes, exit)) {
                None => (None, String::from("exit: no ret")),
                Some(Ok(signature)) => (Some(signature), String::from("eligible")),
                Some(Err(why)) => (None, refusal(why)),
            }
        };
        Self {
            id,
            symbol: function.symbol.clone(),
            image: function.image.clone(),
            address: function.address,
            length: bytes.len(),
            exit,
            verdict,
            signature,
        }
    }

    fn report(&self) -> String {
        let exit = self.exit.map_or(String::from("-"), |exit| exit.to_string());
        format!(
            "{} {} {:#x} {} {exit} {}",
            self.symbol, self.image, self.address, self.length, self.verdict
        )
    }
}

/// A refusal's name and the word's offset.
fn refusal(why: Ineligible) -> String {
    let named = |name: &str, offset: u32| format!("{name} at {offset:#x}");
    match why {
        Ineligible::Length => String::from("length"),
        Ineligible::Exit => String::from("exit"),
        Ineligible::FallsThrough => String::from("falls-through"),
        Ineligible::Masked { offset } => named("masked", offset),
        Ineligible::Call { offset } => named("call", offset),
        Ineligible::RegisterBranch { offset } => named("register-branch", offset),
        Ineligible::System { offset } => named("system", offset),
        Ineligible::Exception { offset } => named("exception", offset),
        Ineligible::Reserved { offset } => named("reserved", offset),
        Ineligible::Exclusive { offset } => named("exclusive", offset),
        Ineligible::Pointer { offset } => named("pointer", offset),
    }
}

/// `bytes` without the padding words after its last word that runs.
fn trimmed(bytes: &[u8]) -> &[u8] {
    let mut end = bytes.len() / 4 * 4;
    while end >= 4 {
        let word = u32::from_le_bytes(bytes[end - 4..end].try_into().expect("a word"));
        if !PADDING.contains(&word) {
            break;
        }
        end -= 4;
    }
    &bytes[..end]
}

/// The byte offset of the first `ret`.
fn first_ret(bytes: &[u8]) -> Option<u16> {
    let (words, _) = bytes.as_chunks::<4>();
    words
        .iter()
        .position(|word| u32::from_le_bytes(*word) == RET)
        .map(|index| (index * 4) as u16)
}

/// The `Signature::generated` line of `row`'s signature, under a comment
/// naming it.
fn line(row: &Row, build: &str) -> String {
    let signature = row.signature.expect("an eligible row");
    let digest = signature
        .digest()
        .iter()
        .map(|byte| format!("{byte:#04x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let variant = match row.id {
        Id::Memmove => "Memmove",
        Id::Bzero => "Bzero",
        Id::Memset => "Memset",
        Id::Memcmp => "Memcmp",
        Id::Strlen => "Strlen",
        #[allow(
            unreachable_patterns,
            reason = "the test routines exist only under test-support"
        )]
        _ => unreachable!("no production table holds a test routine"),
    };
    format!(
        "    // {} {} {build} at {:#x}\n    Signature::generated(\n        Id::{variant},\n        {},\n        {},\n        {:#018x},\n        [{digest}],\n    ),\n",
        row.symbol,
        row.image,
        row.address,
        signature.length(),
        signature.exit(),
        signature.prefix(),
    )
}

/// The `signatures.rs` of `rows`.
fn table(rows: &[&Row], build: &str) -> String {
    let mut out = String::from(
        "//! The signatures of the guest functions HLE replaces, generated offline\n\
         //! from a macOS build's dyld shared cache (`cargo xtask hle-signatures`),\n\
         //! one line per function naming its symbol, image and build. A line holds\n\
         //! the function's routine, length, exit offset and hashes\n\
         //! ([`Signature::generated`]), never its bytes: Stela contains no Apple\n\
         //! software. A function joins the table only once its routine has agreed\n\
         //! with it on the real bytes (`tests/hle_real.rs`).\n\
         use super::{Id, Signature};\n\npub static SIGNATURES: &[Signature] = &[\n",
    );
    let mut seen = Vec::new();
    for row in rows {
        let Some(signature) = row.signature else {
            continue;
        };
        if seen.contains(&signature) {
            continue;
        }
        seen.push(signature);
        let _ = write!(out, "{}", line(row, build));
    }
    out.push_str("];\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOP: u32 = 0xd503_201f;

    /// A 16-word leaf: adds, an inside `b.ne`, a `ret` at word 12, padding.
    fn leaf() -> Vec<u8> {
        let mut words = vec![0x9100_0400u32; 10];
        words[5] = 0x5400_0001 | 2 << 5; // b.ne .+8
        words.extend([0x9100_0400, NOP, RET, 0, 0, NOP]);
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    fn function(bytes: Vec<u8>, address: u64) -> Function {
        Function {
            symbol: String::from("_platform_memmove"),
            image: String::from("/usr/lib/system/libsystem_platform.dylib"),
            address,
            bytes,
        }
    }

    /// The numbers of a generated line, in order.
    fn numbers(line: &str) -> Vec<u64> {
        let code: String = line
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect();
        code.split(|c: char| !(c.is_ascii_hexdigit() || c == 'x'))
            .filter(|token| {
                !token.is_empty() && token.chars().next().is_some_and(|c| c.is_ascii_digit())
            })
            .map(|token| match token.strip_prefix("0x") {
                Some(hex) => u64::from_str_radix(hex, 16).unwrap(),
                None => token.parse().unwrap(),
            })
            .collect()
    }

    #[test]
    fn a_generated_line_reproduces_the_signature() {
        let row = Row::of(Id::Memmove, &function(leaf(), 0x1_8000_0100));
        assert_eq!(row.verdict, "eligible");
        // The trailing UDF and NOP words are padding, not function.
        assert_eq!((row.length, row.exit), (52, Some(48)));
        let line = line(&row, "26B123");
        assert!(
            line.contains("// _platform_memmove /usr/lib/system/libsystem_platform.dylib 26B123")
        );
        let numbers = numbers(&line);
        let digest: Vec<u8> = numbers[3..].iter().map(|&byte| byte as u8).collect();
        let generated = Signature::generated(
            Id::Memmove,
            numbers[0] as u16,
            numbers[1] as u16,
            numbers[2],
            digest.try_into().unwrap(),
        );
        let of = Signature::of(Id::Memmove, &leaf()[..52], 48).unwrap();
        assert_eq!(generated, of);
        assert!(generated.matches(&leaf()));
        assert!(table(&[&row], "26B123").contains("pub static SIGNATURES: &[Signature] = &["));
    }

    #[test]
    fn the_report_names_each_refusal() {
        // Past its page's end.
        let row = Row::of(Id::Memmove, &function(leaf(), 0x1_8000_0fe0));
        assert_eq!(row.verdict, "crosses-page");
        // A word that branches out, a call, and no ret.
        let with = |index: usize, word: u32| {
            let mut bytes = leaf();
            bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            Row::of(Id::Memmove, &function(bytes, 0x1_8000_0000)).verdict
        };
        assert_eq!(with(3, 0x1400_0100), "masked at 0xc");
        assert_eq!(with(3, 0x9400_0001), "call at 0xc");
        assert_eq!(with(12, 0x9100_0400), "exit: no ret");
        assert!(row.report().starts_with(
            "_platform_memmove /usr/lib/system/libsystem_platform.dylib 0x180000fe0 52 48 "
        ));
    }

    #[test]
    fn extracts_stay_out_of_the_repository() {
        assert!(refuse_inside_repository(&crate::tools::root().join("target/hle")).is_err());
        assert!(refuse_inside_repository(Path::new("/tmp/hle-private")).is_ok());
    }

    #[test]
    fn every_production_routine_has_candidates() {
        for id in Id::PRODUCTION {
            assert!(
                CANDIDATES
                    .iter()
                    .any(|(candidate, names)| *candidate == id && !names.is_empty())
            );
        }
    }
}

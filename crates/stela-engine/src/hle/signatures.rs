//! The signatures of the guest functions HLE replaces, generated offline
//! from a macOS build's dyld shared cache (`cargo xtask hle-signatures`),
//! one line per function naming its symbol, image and build. A line holds
//! the function's routine, length, exit offset and hashes
//! ([`Signature::generated`]), never its bytes: Stela contains no Apple
//! software. A function joins the table only once its routine has agreed
//! with it on the real bytes (`tests/hle_real.rs`).
use super::{Id, Signature};

pub static SIGNATURES: &[Signature] = &[
    // __platform_memmove /usr/lib/dyld 26B123 at 0x180489280
    Signature::generated(
        Id::Memmove,
        712,
        132,
        0x382aed947a65d1b0,
        [
            0xe3, 0xe1, 0x83, 0xf4, 0x6e, 0xdd, 0x81, 0xca, 0x86, 0x8b, 0xef, 0x64, 0xf1, 0x72,
            0xbe, 0xb1, 0xe2, 0x07, 0x02, 0xee, 0xd2, 0x22, 0x07, 0x60, 0x73, 0x96, 0x2b, 0xb1,
            0x48, 0xeb, 0x15, 0x10,
        ],
    ),
    // ___bzero /usr/lib/system/libsystem_platform.dylib 26B123 at 0x185555a30
    Signature::generated(
        Id::Bzero,
        308,
        92,
        0x796ff002c8abd53b,
        [
            0x4d, 0x58, 0xc0, 0x41, 0xfa, 0xde, 0x73, 0x5c, 0xf2, 0x4b, 0xb5, 0xbe, 0x7a, 0xcf,
            0x11, 0x37, 0x30, 0x73, 0x94, 0x61, 0xda, 0x61, 0xf9, 0xa7, 0x7e, 0xde, 0x16, 0xf7,
            0xc3, 0xf3, 0xc8, 0x1d,
        ],
    ),
];

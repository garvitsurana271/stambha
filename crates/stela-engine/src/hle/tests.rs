use super::*;
use alloc::vec::Vec;

const NOP: u32 = 0xd503_201f;
const RET: u32 = 0xd65f_03c0;
/// The synthetic leaf's exit: its `ret` at word 60.
const EXIT: u16 = 240;
/// The word [`replaced`] puts a refused or masked word at.
const SLOT: usize = 30;

/// `add xN, xN, #imm`.
fn add(register: u32, immediate: u32) -> u32 {
    0x9100_0000 | (immediate & 0xfff) << 10 | register << 5 | register
}
/// `b.ne` by `words` from the branch.
fn b_ne(words: i32) -> u32 {
    0x5400_0001 | ((words as u32) & 0x7ffff) << 5
}
/// `cbz x3` by `words` from the branch.
fn cbz_x3(words: i32) -> u32 {
    0xb400_0003 | ((words as u32) & 0x7ffff) << 5
}
/// `b` by `words` from the branch.
fn b(words: i32) -> u32 {
    0x1400_0000 | ((words as u32) & 0x03ff_ffff)
}

fn bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// A self-contained 64-word leaf: `add`s, an inside `b.ne` and `cbz`, its
/// `ret` at word 60, NOP padding and a last `ret`.
fn leaf_words() -> Vec<u32> {
    let mut words = vec![NOP; 64];
    for (index, word) in words.iter_mut().enumerate().take(60) {
        *word = add(index as u32 % 8, index as u32 + 1);
    }
    words[10] = b_ne(5);
    words[20] = cbz_x3(30);
    words[60] = RET;
    words[63] = RET;
    words
}

fn leaf() -> Vec<u8> {
    bytes(&leaf_words())
}

/// The leaf with word [`SLOT`] replaced by `word`.
fn replaced(word: u32) -> Vec<u8> {
    let mut words = leaf_words();
    words[SLOT] = word;
    bytes(&words)
}

fn masked_stream(function: &[u8]) -> Vec<u32> {
    let length = function.len() as u32;
    let (words, _) = function.as_chunks::<4>();
    words
        .iter()
        .enumerate()
        .map(|(index, word)| mask_word(u32::from_le_bytes(*word), index as u32 * 4, length))
        .collect()
}

#[test]
fn a_signature_matches_its_own_bytes() {
    let function = leaf();
    let signature = Signature::of(Id::Memmove, &function, EXIT).unwrap();
    assert!(signature.matches(&function));
    assert_eq!(signature.id(), Id::Memmove);
    assert_eq!(signature.length(), 256);
    assert_eq!(signature.exit(), 240);
}

#[test]
fn every_changed_unmasked_bit_misses() {
    let function = leaf();
    let signature = Signature::of(Id::Memmove, &function, EXIT).unwrap();
    for word in 0..function.len() / 4 {
        for bit in 0..32 {
            let mut changed = function.clone();
            let mut value = u32::from_le_bytes(changed[word * 4..word * 4 + 4].try_into().unwrap());
            value ^= 1 << bit;
            changed[word * 4..word * 4 + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                !signature.matches(&changed) || Signature::of(Id::Memmove, &changed, EXIT).is_err(),
                "word {word} bit {bit}: {value:#010x} still matches"
            );
        }
    }
}

#[test]
fn an_outside_branch_is_masked_and_an_inside_one_is_not() {
    // Forward and backward out of the function: only the opcode is left.
    let ahead = replaced(b(100));
    let behind = replaced(b(-100));
    assert_ne!(ahead, behind);
    assert_eq!(masked_stream(&ahead), masked_stream(&behind));
    for function in [&ahead, &behind] {
        assert_eq!(
            eligible(function, EXIT),
            Err(Ineligible::Masked {
                offset: SLOT as u32 * 4
            })
        );
    }
    // An inside branch keeps its immediate: another target misses.
    let function = leaf();
    let signature = Signature::of(Id::Memmove, &function, EXIT).unwrap();
    let mut words = leaf_words();
    words[10] = b_ne(6);
    let retargeted = bytes(&words);
    assert_eq!(eligible(&retargeted, EXIT), Ok(()));
    assert!(!signature.matches(&retargeted));
    // A branch to the word after the last is outside.
    assert_eq!(
        eligible(&replaced(b(64 - SLOT as i32)), EXIT),
        Err(Ineligible::Masked {
            offset: SLOT as u32 * 4
        })
    );
    assert_eq!(eligible(&replaced(b(63 - SLOT as i32)), EXIT), Ok(()));
}

#[test]
fn an_outside_branch_never_matches_a_branch_to_itself() {
    // `b .` is inside and keeps its zero offset; `b` out of the function
    // masks to the same word, which the digest's flag tells apart.
    let itself = replaced(b(0));
    let signature = Signature::of(Id::Memmove, &itself, EXIT).unwrap();
    for outside in [b(100), b(-100), b(64 - SLOT as i32)] {
        let candidate = replaced(outside);
        assert_eq!(
            masked_stream(&candidate),
            masked_stream(&itself),
            "{outside:#010x}"
        );
        assert!(!signature.matches(&candidate), "{outside:#010x}");
    }
    // An outside B.cond, CBZ or TBZ masks to its own branch to itself too.
    for (inside, outside) in [
        (b_ne(0), b_ne(0x1000)),
        (cbz_x3(0), cbz_x3(-0x1000)),
        (0x3600_0002, 0x3600_0002 | (0x1000 << 5)), // tbz w2,#0
    ] {
        let signature = Signature::of(Id::Memmove, &replaced(inside), EXIT).unwrap();
        assert!(signature.matches(&replaced(inside)), "{inside:#010x}");
        assert!(!signature.matches(&replaced(outside)), "{outside:#010x}");
    }
}

#[test]
fn a_function_ends_in_ret_or_a_branch_back_inside() {
    let mut words = leaf_words();
    for (last, verdict) in [
        (RET, Ok(())),
        (b(-3), Ok(())),
        (NOP, Err(Ineligible::FallsThrough)),
        (add(1, 1), Err(Ineligible::FallsThrough)),
        // A conditional branch falls through when it is not taken.
        (b_ne(-3), Err(Ineligible::FallsThrough)),
        (cbz_x3(-3), Err(Ineligible::FallsThrough)),
        // Out of the function: masked before its place is looked at.
        (b(1), Err(Ineligible::Masked { offset: 252 })),
    ] {
        words[63] = last;
        assert_eq!(eligible(&bytes(&words), EXIT), verdict, "{last:#010x}");
    }
}

#[test]
fn every_pc_relative_form_is_masked() {
    // B/BL, B.cond and BC.cond, CBZ/CBNZ (W and X) and TBZ/TBNZ, all to
    // outside the function; ADR, ADRP and the literal loads whatever their
    // immediate. Each loses exactly its PC-relative field.
    const IMM26: u32 = 0x03ff_ffff;
    const IMM19: u32 = 0x00ff_ffe0;
    const IMM14: u32 = 0x0007_ffe0;
    const ADR: u32 = 0x60ff_ffe0;
    for (word, field) in [
        (0x1400_0064, IMM26),                       // b +100 words
        (0x9400_0064, IMM26),                       // bl +100 words
        (0x5400_0000 | (0x1000 << 5), IMM19),       // b.eq +0x1000 words
        (0x5400_0010 | (0x1000 << 5), IMM19),       // bc.eq +0x1000 words
        (0x3400_0000 | (0x1000 << 5) | 1, IMM19),   // cbz w1
        (0xb500_0000 | (0x7_f000 << 5) | 1, IMM19), // cbnz x1, backward
        (0x3600_0000 | (0x1000 << 5) | 2, IMM14),   // tbz w2,#0
        (0xb700_0000 | (0x2000 << 5) | 2, IMM14),   // tbnz x2,#32, backward
        (0x1000_0000, ADR),                         // adr x0, .
        (0x9000_0000, ADR),                         // adrp x0, .
        (0xb000_0021, ADR),                         // adrp x1, .+5 pages
        (0x5800_0000, IMM19),                       // ldr x0, .
        (0x1800_0020, IMM19),                       // ldr w0, .+4
        (0x9800_0000, IMM19),                       // ldrsw x0, .
        (0xd800_0000, IMM19),                       // prfm pldl1keep, .
        (0x5c00_0000, IMM19),                       // ldr d0, .
    ] {
        assert_eq!(
            eligible(&replaced(word), EXIT),
            Err(Ineligible::Masked {
                offset: SLOT as u32 * 4
            }),
            "{word:#010x}"
        );
        assert_eq!(
            masked_stream(&replaced(word))[SLOT],
            word & !field,
            "{word:#010x}"
        );
    }
}

#[test]
fn a_prefix_collision_still_needs_the_digest() {
    let function = leaf();
    let signature = Signature::of(Id::Memmove, &function, EXIT).unwrap();
    let head: &[u8; PREFIX_BYTES] = function[..PREFIX_BYTES].try_into().unwrap();
    assert_eq!(signature.prefix(), prefix_hash(head, 256));
    let forged = Signature::generated(Id::Memmove, 256, EXIT, signature.prefix(), [0; 32]);
    assert!(!forged.matches(&function));
    // With its digest too, a generated signature is the computed one.
    let generated = Signature::generated(
        Id::Memmove,
        256,
        EXIT,
        signature.prefix(),
        *signature.digest(),
    );
    assert_eq!(generated, signature);
    assert!(generated.matches(&function));
}

#[test]
fn the_prefix_hash_depends_on_the_length() {
    // A branch inside 64 words is outside 32: the same head masks apart.
    let mut words = leaf_words();
    words[2] = b(40);
    let head: [u8; PREFIX_BYTES] = bytes(&words[..8]).try_into().unwrap();
    assert_ne!(prefix_hash(&head, 256), prefix_hash(&head, 128));
}

#[test]
fn eligibility_names_each_refused_class() {
    let offset = SLOT as u32 * 4;
    for (word, refusal) in [
        (0x9400_0000, Ineligible::Call { offset }), // bl . (inside)
        (0xd61f_0200, Ineligible::RegisterBranch { offset }), // br x16
        (0xd400_0001, Ineligible::Exception { offset }), // svc #0
        (0xd51b_d040, Ineligible::System { offset }), // msr tpidr_el0, x0
        (0xc85f_7c20, Ineligible::Exclusive { offset }), // ldxr x0,[x1]
        (0xf820_8020, Ineligible::Exclusive { offset }), // swp x0,x0,[x1]
        (0xc8df_fc20, Ineligible::Exclusive { offset }), // ldar x0,[x1]
        (0xb8bf_c020, Ineligible::Exclusive { offset }), // ldapr w0,[x1]
        (0x9940_0020, Ineligible::Exclusive { offset }), // ldapur w0,[x1]
        (0xd900_0020, Ineligible::Exclusive { offset }), // stlur x0,[x1]
        (0x1d00_0820, Ineligible::Exclusive { offset }), // stlur b0,[x1]
        (0xd920_0820, Ineligible::Exclusive { offset }), // stg x0,[x1]
        (0x0000_0000, Ineligible::Reserved { offset }), // udf #0
        (0x0020_1000, Ineligible::Reserved { offset }), // AMX ldx x0
        (0x0020_1143, Ineligible::Reserved { offset }), // AMX fma64 x3
        (0x0020_1420, Ineligible::Reserved { offset }), // GXF genter
        (0xd503_237f, Ineligible::System { offset }), // pacibsp
        (0xdac1_0020, Ineligible::Pointer { offset }), // pacia x0, x1
        (0xf820_0420, Ineligible::Pointer { offset }), // ldraa x0,[x1]
        (0x9ac2_3020, Ineligible::Pointer { offset }), // pacga x0, x1, x2
        (0x9000_0000, Ineligible::Masked { offset }), // adrp x0, 0
    ] {
        assert_eq!(
            eligible(&replaced(word), EXIT),
            Err(refusal),
            "{word:#010x}"
        );
    }
    for word in [
        0xd50b_7423, // dc zva, x3
        0xd503_245f, // bti c
        0xd503_241f, // bti
        0xd53b_00e4, // mrs x4, dczid_el0
        NOP,
    ] {
        assert_eq!(eligible(&replaced(word), EXIT), Ok(()), "{word:#010x}");
    }
    let function = leaf();
    // Too short, not whole words, too long.
    assert_eq!(eligible(&function[..28], 24), Err(Ineligible::Length));
    assert_eq!(eligible(&function[..254], EXIT), Err(Ineligible::Length));
    let long = bytes(&[NOP; 1025]);
    assert_eq!(eligible(&long, EXIT), Err(Ineligible::Length));
    // The exit out of the function, not a word, at the entry, or no `ret`.
    for exit in [256, 1000, 242, 0, 236] {
        assert_eq!(eligible(&function, exit), Err(Ineligible::Exit), "{exit}");
    }
    // A RET through another register is a register branch.
    assert_eq!(
        eligible(&replaced(0xd65f_0200), EXIT),
        Err(Ineligible::RegisterBranch { offset })
    );
}

#[test]
fn bytes_shorter_than_the_length_never_match() {
    let function = leaf();
    let signature = Signature::of(Id::Memmove, &function, EXIT).unwrap();
    for length in [0, 31, 32, 252] {
        assert!(!signature.matches(&function[..length]), "{length}");
    }
    // Bytes past the function are not its own.
    let mut longer = function.clone();
    longer.extend_from_slice(&[0xff; 64]);
    assert!(signature.matches(&longer));
}

#[test]
fn ids_are_the_compiler_s_routines() {
    // The routines' own tests are the compiler's (`x86_64::hle`); an id
    // here is one of them, test routines included.
    let routine: stela_compiler::x86_64::hle::Routine = Id::Touch;
    assert_eq!(routine.name(), "touch");
    assert_eq!(Id::from_name("memmove"), Some(Id::Memmove));
}

/// A table of two functions: the leaf as memmove and another as bzero.
fn two_routines() -> alloc::sync::Arc<[Signature]> {
    alloc::sync::Arc::from([
        Signature::of(Id::Memmove, &leaf(), EXIT).unwrap(),
        Signature::of(Id::Bzero, &replaced(NOP), EXIT).unwrap(),
    ])
}

#[test]
fn an_off_config_enables_nothing() {
    let off = Config::off();
    assert_eq!(off.enabled, 0);
    assert!(off.table.is_empty());
    assert_eq!(off.max_bytes, Config::MAX_BYTES);
    assert_eq!(Config::default(), off);
    for routine in Id::PRODUCTION.into_iter().chain([Id::Bail, Id::Touch]) {
        assert!(!off.enables(routine), "{routine:?}");
    }
    // Without --hle a boot is off whatever its table; with --hle the
    // generated table enables every routine it holds.
    assert_eq!(config::booted(false, &[], two_routines()), off);
    assert_eq!(Config::boot(false, &[]), off);
    assert_eq!(
        Config::boot(true, &[]).enabled,
        Id::Memmove.bit() | Id::Bzero.bit()
    );
    // A routine without a signature is never enabled.
    assert_eq!(Config::with_table(two_routines(), &[Id::Strlen]).enabled, 0);
}

#[test]
fn hle_off_clears_only_its_ids() {
    let both = config::booted(true, &[], two_routines());
    assert!(both.enables(Id::Memmove) && both.enables(Id::Bzero));
    assert_eq!(both.enabled, Id::Memmove.bit() | Id::Bzero.bit());
    let without_bzero = config::booted(true, &[Id::Bzero], two_routines());
    assert_eq!(without_bzero.enabled, Id::Memmove.bit());
    assert_eq!(without_bzero.table, two_routines());
    // Naming a routine the table lacks clears nothing else.
    let without_strlen = config::booted(true, &[Id::Strlen], two_routines());
    assert_eq!(without_strlen.enabled, both.enabled);
    assert_eq!(
        Config::with_table(two_routines(), &[Id::Memmove, Id::Strlen]).enabled,
        Id::Memmove.bit()
    );
}

#[test]
fn max_bytes_takes_its_bounds() {
    for bytes in [256, 4096, 1 << 20] {
        assert_eq!(Config::off().with_max_bytes(bytes).max_bytes, bytes);
    }
}

#[test]
#[should_panic(expected = "256 bytes to 1 MiB")]
fn max_bytes_below_its_bounds_panics() {
    Config::off().with_max_bytes(255);
}

#[test]
#[should_panic(expected = "256 bytes to 1 MiB")]
fn max_bytes_above_its_bounds_panics() {
    Config::off().with_max_bytes((1 << 20) + 1);
}

#[test]
fn refusals_are_named_once_in_their_order() {
    for (index, refusal) in Refusal::ALL.into_iter().enumerate() {
        assert_eq!(refusal as usize, index, "{refusal:?}");
        let named = Refusal::ALL
            .iter()
            .filter(|other| other.name() == refusal.name());
        assert_eq!(named.count(), 1, "{refusal:?}");
    }
    let mut statistics = Statistics::default();
    statistics.refuse(Refusal::Admitted);
    assert_eq!(statistics.refusals(Refusal::Admitted), 1);
    assert_eq!(statistics.refused.iter().sum::<u64>(), 1);
}

#[test]
#[should_panic(expected = "at most 64 signatures")]
fn a_table_of_more_than_64_signatures_panics() {
    let signature = Signature::of(Id::Memmove, &leaf(), EXIT).unwrap();
    Config::with_table(alloc::sync::Arc::from(vec![signature; 65]), &[Id::Memmove]);
}

#[test]
fn statistics_line_names_every_counter() {
    let mut statistics = Statistics {
        matched: 9,
        matched_signatures: 0b101,
        installed: 3,
        bypassed: 2,
        ..Statistics::default()
    };
    statistics.refuse(Refusal::CrossesPage);
    statistics.refuse(Refusal::Compose);
    statistics.refuse(Refusal::Compose);
    assert_eq!(
        statistics.line(4, 5),
        "PES HLE pe=4 matched=2/5 installed=3 bypassed=2 refused=breakpoint:0,crosses-page:1,\
         device-site:0,admitted:0,bail:0,compose:2"
    );
}

#[test]
fn a_boot_config_describes_its_routines() {
    let signature = Signature::of(Id::Memmove, &leaf(), EXIT).unwrap();
    let table: alloc::sync::Arc<[Signature]> = alloc::sync::Arc::from([signature]);
    let on = Config::with_table(table.clone(), &[Id::Memmove]);
    assert_eq!(
        on.describe(&[Id::Strlen]),
        "on signatures=1 ids=memmove off=strlen max=65536"
    );
    let none = Config::with_table(table, &[]);
    assert_eq!(
        none.describe(&[Id::Memmove]),
        "on signatures=1 ids=- off=memmove max=65536: no signature is enabled, so no function is replaced"
    );
    assert_eq!(
        Config::boot(true, &[]).describe(&[]),
        "on signatures=2 ids=memmove,bzero off=- max=65536"
    );
}

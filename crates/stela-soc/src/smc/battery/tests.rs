use super::super::*;
use super::{ASLEEP_RETRY_MILLIS, SPACING_MILLIS};
use stela_drivers::platform::power_snapshot::{
    BatteryState, Name, PowerSnapshot, Status, TestState,
};

const BASE: u64 = 0x2_3fe0_0000;
/// The Mac mini's table: its own keys and J473AP's `pKW4` GPIO keys.
const J473_GPIO_KEYS: [&[u8; 4]; 8] = [
    b"gP09", b"gP0d", b"gP0f", b"gP10", b"gP15", b"gP16", b"gP18", b"pmVC",
];
const MAC_MINI_KEYS: u32 = 26;

/// Every battery key: name, type, size and flags.
const TABLE: [(&[u8; 4], &[u8; 4], u8, u8); 33] = [
    (b"AC-N", b"ui8 ", 1, READABLE),
    (b"AC-W", b"ui8 ", 1, READABLE),
    (b"B0AC", b"si16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0AV", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0CM", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0CT", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0DC", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0FC", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0IV", b"si16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0RM", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0TE", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0TF", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"B0UC", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"BCF0", b"flag", 1, READABLE),
    (b"BDFU", b"ui64", 8, READABLE | WRITABLE | LITTLE_ENDIAN),
    (b"BMDN", b"ch8*", 32, READABLE),
    (b"BMSN", b"ch8*", 32, READABLE),
    (b"BPCC", b"ui16", 2, READABLE | LITTLE_ENDIAN),
    (b"BSCL", b"ui8 ", 1, READABLE | WRITABLE),
    (b"BSFC", b"flag", 1, READABLE),
    (b"BUIC", b"ui8 ", 1, READABLE),
    (b"CH0C", b"ui8 ", 1, READABLE | WRITABLE),
    (b"CH0I", b"ui8 ", 1, READABLE | WRITABLE),
    (b"CHCC", b"ui8 ", 1, READABLE),
    (b"CHCE", b"flag", 1, READABLE),
    (b"CHSC", b"ui8 ", 1, READABLE),
    (b"CHTE", b"ui32", 4, READABLE | WRITABLE | LITTLE_ENDIAN),
    (b"D0IG", b"ui8 ", 1, READABLE | WRITABLE),
    (b"MSLD", b"ui8 ", 1, READABLE),
    (b"UB0C", b"ui8 ", 1, READABLE | WRITABLE),
    (b"UB0T", b"ui64", 8, READABLE | WRITABLE | LITTLE_ENDIAN),
    (b"WAFC", b"ui32", 4, READABLE | WRITABLE | LITTLE_ENDIAN),
    (b"bfD0", b"ui32", 4, READABLE | WRITABLE | LITTLE_ENDIAN),
];

fn request(kind: u8, id: u8, size: u8, write_size: u8, key: u32) -> u64 {
    u64::from(kind)
        | u64::from(id) << 12
        | u64::from(size) << 16
        | u64::from(write_size) << 24
        | u64::from(key) << 32
}

fn mac_mini() -> (Smc, Sram) {
    let sram = Sram::default();
    let keys = J473_GPIO_KEYS
        .iter()
        .map(|name| (code(name), Key::gpio()))
        .collect();
    (Smc::new(sram.clone(), BASE, keys).unwrap(), sram)
}

fn send(smc: &mut Smc, payload: u64) -> u64 {
    let mut outbox = Vec::new();
    smc.receive(payload, &mut outbox).unwrap();
    assert_eq!(outbox.len(), 1);
    outbox[0]
}

/// The value of `name` as a read returns it, inline or from the page.
fn read(smc: &mut Smc, sram: &Sram, name: &[u8; 4]) -> Vec<u8> {
    let reply = send(smc, request(READ, 1, MAX_VALUE as u8, 0, code(name)));
    assert_eq!(
        reply as u8,
        SUCCESS,
        "{}",
        core::str::from_utf8(name).unwrap()
    );
    let size = (reply >> 16 & 0xff) as usize;
    if size <= 4 {
        ((reply >> 32) as u32).to_le_bytes()[..size].to_vec()
    } else {
        sram.get(size)
    }
}

fn result(smc: &mut Smc, kind: u8, size: u8, name: &[u8; 4]) -> u8 {
    send(smc, request(kind, 2, size, size, code(name))) as u8
}

fn enable_notifications(smc: &mut Smc, sram: &Sram) {
    sram.put(&[1]);
    assert_eq!(result(smc, WRITE, 1, b"NTAP"), SUCCESS);
}

fn notifications(smc: &mut Smc) -> Vec<u64> {
    let mut outbox = Vec::new();
    smc.poll(&mut outbox).unwrap();
    outbox
}

fn discharging() -> BatteryState {
    BatteryState {
        status: Status::Discharging,
        percent: Some(73),
        remaining_mah: Some(3_650),
        full_mah: Some(5_000),
        design_mah: Some(5_200),
        warning_mah: Some(500),
        low_mah: Some(150),
        low_trusted: true,
        voltage_mv: Some(15_800),
        current_ma: Some(-2_850),
        power_mw: Some(45_030),
        cycle_count: Some(42),
        time_to_empty_min: Some(77),
        time_to_full_min: None,
        critical: false,
        critical_bit: false,
        model: Name::new(b"A32-K55"),
        serial: Name::new(b"0123"),
    }
}

fn on_battery() -> PowerSnapshot {
    PowerSnapshot {
        ac_online: Some(false),
        battery: Some(discharging()),
    }
}

fn charging() -> PowerSnapshot {
    PowerSnapshot {
        ac_online: Some(true),
        battery: Some(BatteryState {
            status: Status::Charging,
            current_ma: Some(1_900),
            time_to_empty_min: None,
            time_to_full_min: Some(42),
            ..discharging()
        }),
    }
}

fn with_battery() -> (Smc, Sram) {
    let (mut smc, sram) = mac_mini();
    smc.add_battery(&on_battery()).unwrap();
    (smc, sram)
}

/// Every reply the SMC's table gives: each index's key, and each key's
/// information and value.
fn table_replies(smc: &mut Smc, sram: &Sram) -> Vec<(u64, Vec<u8>)> {
    let mut replies = Vec::new();
    let count = smc.keys.len() + usize::from(smc.rtc.is_some());
    for index in 0..=count {
        let reply = send(smc, request(KEY_BY_INDEX, 0, 0, 0, index as u32));
        replies.push((reply, Vec::new()));
        if reply as u8 != SUCCESS {
            continue;
        }
        let name = ((reply >> 32) as u32).swap_bytes();
        let info = send(smc, request(KEY_INFO, 0, 0, 0, name));
        replies.push((info, sram.get(6)));
        let value = send(smc, request(READ, 0, MAX_VALUE as u8, 0, name));
        let size = (value >> 16 & 0xff) as usize;
        replies.push((value, if size > 4 { sram.get(size) } else { Vec::new() }));
    }
    replies
}

#[test]
fn an_smc_given_no_battery_answers_as_the_mac_minis_whatever_the_host_reads() {
    let (mut smc, sram) = mac_mini();
    let (mut fresh, fresh_sram) = mac_mini();
    let reply = send(&mut smc, request(READ, 0, 4, 0, KEY_COUNT));
    assert_eq!((reply >> 32) as u32, MAC_MINI_KEYS.to_be());
    for (name, _, size, _) in TABLE {
        for kind in [READ, KEY_INFO, WRITE] {
            assert_eq!(
                result(&mut smc, kind, size, name),
                KEY_NOT_FOUND,
                "{}",
                core::str::from_utf8(name).unwrap()
            );
        }
    }
    // Nor is any request kept for the log.
    assert_eq!(smc.take_key_request(), None);
    // Host readings reach an SMC with no battery as nothing at all.
    enable_notifications(&mut smc, &sram);
    enable_notifications(&mut fresh, &fresh_sram);
    assert_eq!(smc.power(&on_battery(), 1_000), None);
    assert_eq!(smc.power(&charging(), 60_000), None);
    assert_eq!(smc.power_due(120_000), None);
    assert!(notifications(&mut smc).is_empty());
    assert_eq!(
        table_replies(&mut smc, &sram),
        table_replies(&mut fresh, &fresh_sram)
    );
    // Low-power emergency mode still needs a battery.
    sram.put(&code(b"lpem").to_le_bytes());
    assert!(
        smc.receive(request(WRITE, 0, 4, 0, SYSTEM_EVENT), &mut Vec::new())
            .is_err()
    );
    assert!(smc.take_transition().is_none());
}

#[test]
fn battery_keys_declare_the_types_and_sizes_macos_decodes() {
    let (mut smc, sram) = with_battery();
    let reply = send(&mut smc, request(READ, 0, 4, 0, KEY_COUNT));
    assert_eq!(
        (reply >> 32) as u32,
        (MAC_MINI_KEYS + TABLE.len() as u32).to_be()
    );
    for (name, kind, size, flags) in TABLE {
        let reply = send(&mut smc, request(KEY_INFO, 0, 0, 0, code(name)));
        assert_eq!(reply as u8, SUCCESS);
        let mut info = vec![size];
        info.extend_from_slice(kind);
        info.push(flags);
        assert_eq!(sram.get(6), info, "{}", core::str::from_utf8(name).unwrap());
    }
    // The table still enumerates sorted, each key once.
    let names: Vec<u32> = (0..smc.keys.len())
        .map(|index| smc.key_by_index(index).unwrap())
        .collect();
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    for (name, ..) in TABLE {
        assert!(names.contains(&code(name)));
    }
    assert_eq!(
        send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, names.len() as u32)) as u8,
        INDEX_RANGE
    );
}

#[test]
fn bpcc_reports_one_pack_and_no_charger_as_the_battery_driver_decodes_it() {
    let (mut smc, sram) = with_battery();
    // `AppleSmartBattery::_smcReadKey` uses `smcReadKeyHostEndian`, which
    // swaps 2-byte keys unless `LITTLE_ENDIAN` (bit 2) is set in attributes.
    let info = send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"BPCC")));
    assert_eq!(info as u8, SUCCESS);
    assert_ne!(sram.get(6)[5] & LITTLE_ENDIAN, 0);
    let value = read(&mut smc, &sram, b"BPCC");
    assert_eq!(value, [0x00, 0x01]);
    // `smcNotifierHandler`: LDRH, then the high byte is the pack count.
    let word = u16::from_le_bytes(value[..].try_into().unwrap());
    assert_eq!((word >> 8, word & 0xff), (1, 0));
}

#[test]
fn values_encode_the_snapshot_in_each_keys_type_and_byte_order() {
    let (mut smc, sram) = with_battery();
    let le16 = |value: u16| value.to_le_bytes().to_vec();
    let check = |smc: &mut Smc, expected: &[(&[u8; 4], Vec<u8>)]| {
        for (name, value) in expected {
            assert_eq!(
                &read(smc, &sram, name),
                value,
                "{}",
                core::str::from_utf8(*name).unwrap()
            );
        }
    };
    let mut model = vec![0u8; 32];
    model[..7].copy_from_slice(b"A32-K55");
    let mut serial = vec![0u8; 32];
    serial[..4].copy_from_slice(b"0123");
    check(
        &mut smc,
        &[
            (b"B0AV", le16(15_800)),
            (b"B0AC", (-2_850i16).to_le_bytes().to_vec()),
            (b"B0IV", (-2_850i16).to_le_bytes().to_vec()),
            (b"B0UC", le16(3_650)),
            (b"B0CM", le16(5_000)),
            (b"B0TE", le16(77)),
            (b"B0TF", le16(0xffff)),
            (b"B0CT", le16(42)),
            (b"BMDN", model),
            (b"BMSN", serial),
            (b"CHSC", vec![0]),
            (b"CHCE", vec![0]),
            (b"CHCC", vec![0]),
            (b"BSFC", vec![0]),
            (b"BCF0", vec![0]),
            (b"AC-N", vec![0]),
            (b"AC-W", vec![0]),
            (b"BUIC", vec![73]),
            // Little-endian with a 1-byte BCF0: Linux macsmc-power swaps
            // B0RM only on firmware older than macOS 27's, which it tells by
            // a 4-byte BCF0.
            (b"B0RM", le16(3_650)),
            (b"B0FC", le16(5_000)),
            (b"B0DC", le16(5_200)),
            (b"MSLD", vec![0]),
            (b"CH0C", vec![0]),
            (b"BDFU", vec![0; 8]),
        ],
    );
    assert_eq!(smc.power(&charging(), 0), None);
    check(
        &mut smc,
        &[
            (b"B0AC", le16(1_900)),
            (b"B0IV", le16(1_900)),
            (b"B0TE", le16(0xffff)),
            (b"B0TF", le16(42)),
            (b"CHSC", vec![1]),
            (b"CHCE", vec![1]),
            (b"CHCC", vec![1]),
            (b"AC-N", vec![1]),
            (b"AC-W", vec![1]),
            (b"BSFC", vec![0]),
        ],
    );
    let full = PowerSnapshot {
        ac_online: Some(true),
        battery: Some(BatteryState {
            status: Status::Full,
            percent: Some(100),
            remaining_mah: Some(5_000),
            current_ma: Some(0),
            time_to_empty_min: None,
            time_to_full_min: None,
            ..discharging()
        }),
    };
    smc.power(&full, 0);
    check(
        &mut smc,
        &[
            (b"BSFC", vec![1]),
            (b"CHSC", vec![0]),
            (b"B0AC", le16(0)),
            (b"BUIC", vec![100]),
            (b"B0UC", le16(5_000)),
            (b"B0RM", le16(5_000)),
        ],
    );
    // Critical, and values past each type's range held at its ends.
    let extreme = PowerSnapshot {
        ac_online: Some(false),
        battery: Some(BatteryState {
            critical: true,
            remaining_mah: Some(70_000),
            voltage_mv: Some(u32::MAX),
            current_ma: Some(-40_000),
            cycle_count: Some(100_000),
            time_to_empty_min: Some(70_000),
            ..discharging()
        }),
    };
    smc.power(&extreme, 0);
    check(
        &mut smc,
        &[
            (b"BCF0", vec![1]),
            (b"B0UC", le16(0xffff)),
            (b"B0RM", le16(0xffff)),
            (b"B0AV", le16(0xffff)),
            (b"B0AC", i16::MIN.to_le_bytes().to_vec()),
            (b"B0CT", le16(0xffff)),
            (b"B0TE", le16(0xfffe)),
        ],
    );
    let surge = PowerSnapshot {
        ac_online: Some(true),
        battery: Some(BatteryState {
            current_ma: Some(40_000),
            ..charging().battery.unwrap()
        }),
    };
    smc.power(&surge, 0);
    check(&mut smc, &[(b"B0AC", i16::MAX.to_le_bytes().to_vec())]);
}

#[test]
fn a_reading_that_lost_a_value_keeps_the_last_known_one() {
    let (mut smc, sram) = with_battery();
    let partial = PowerSnapshot {
        ac_online: None,
        battery: Some(BatteryState {
            percent: None,
            remaining_mah: None,
            voltage_mv: None,
            current_ma: None,
            cycle_count: None,
            time_to_empty_min: None,
            ..discharging()
        }),
    };
    smc.power(&partial, 0);
    assert_eq!(read(&mut smc, &sram, b"B0UC"), 3_650u16.to_le_bytes());
    assert_eq!(read(&mut smc, &sram, b"B0AV"), 15_800u16.to_le_bytes());
    assert_eq!(read(&mut smc, &sram, b"BUIC"), [73]);
    assert_eq!(read(&mut smc, &sram, b"B0CT"), 42u16.to_le_bytes());
    assert_eq!(read(&mut smc, &sram, b"B0AC"), (-2_850i16).to_le_bytes());
    // A time estimate that went away is none, not the last one.
    assert_eq!(read(&mut smc, &sram, b"B0TE"), 0xffffu16.to_le_bytes());
    // An unknown AC state keeps the last known one.
    assert_eq!(read(&mut smc, &sram, b"CHCE"), [0]);
    // The current of another status is not kept.
    let started = PowerSnapshot {
        ac_online: Some(true),
        battery: Some(BatteryState {
            status: Status::Charging,
            current_ma: None,
            ..discharging()
        }),
    };
    smc.power(&started, 0);
    assert_eq!(read(&mut smc, &sram, b"B0AC"), [0, 0]);
    // A battery that read as nothing keeps every value.
    smc.power(
        &PowerSnapshot {
            ac_online: Some(true),
            battery: None,
        },
        0,
    );
    assert_eq!(read(&mut smc, &sram, b"B0UC"), 3_650u16.to_le_bytes());
    assert_eq!(read(&mut smc, &sram, b"CHCE"), [1]);
}

#[test]
fn an_incomplete_reading_or_a_table_the_ap_has_read_keeps_the_mac_minis_keys() {
    for battery in [
        BatteryState {
            percent: None,
            ..discharging()
        },
        BatteryState {
            remaining_mah: None,
            ..discharging()
        },
        BatteryState {
            full_mah: None,
            ..discharging()
        },
        // A reading at 0, which macOS takes as an empty battery and shuts
        // down at: a percentage or a remaining charge of 0.
        BatteryState {
            percent: Some(0),
            ..discharging()
        },
        BatteryState {
            remaining_mah: Some(0),
            ..discharging()
        },
    ] {
        let (mut smc, _) = mac_mini();
        let reading = PowerSnapshot {
            ac_online: Some(false),
            battery: Some(battery),
        };
        assert!(smc.add_battery(&reading).is_err(), "{battery:?}");
        assert!(smc.battery.is_none());
        assert_eq!(smc.keys.len() as u32, MAC_MINI_KEYS);
    }
    // Once the AP has read the key count or a key by its index, the table
    // is the one it keeps: no battery joins it.
    let (mut smc, _) = mac_mini();
    send(&mut smc, request(READ, 0, 4, 0, KEY_COUNT));
    assert!(smc.add_battery(&on_battery()).is_err());
    assert_eq!(smc.keys.len() as u32, MAC_MINI_KEYS);
    let (mut smc, _) = mac_mini();
    send(&mut smc, request(KEY_BY_INDEX, 0, 0, 0, 3));
    assert!(smc.add_battery(&on_battery()).is_err());
    // One key's information does not.
    let (mut smc, _) = mac_mini();
    send(&mut smc, request(KEY_INFO, 0, 0, 0, code(b"MBSW")));
    smc.add_battery(&on_battery()).unwrap();
}

#[test]
fn the_first_reading_after_attach_that_lost_every_value_keeps_the_attached_ones() {
    let (mut smc, sram) = with_battery();
    let lost = PowerSnapshot {
        ac_online: None,
        battery: Some(BatteryState {
            percent: None,
            remaining_mah: None,
            full_mah: None,
            design_mah: None,
            voltage_mv: None,
            current_ma: None,
            power_mw: None,
            cycle_count: None,
            time_to_empty_min: None,
            ..discharging()
        }),
    };
    smc.power(&lost, 0);
    for (name, value) in [
        (b"BUIC", vec![73]),
        (b"B0UC", 3_650u16.to_le_bytes().to_vec()),
        (b"B0CM", 5_000u16.to_le_bytes().to_vec()),
        (b"B0DC", 5_200u16.to_le_bytes().to_vec()),
        (b"B0AV", 15_800u16.to_le_bytes().to_vec()),
        (b"CHCE", vec![0]),
    ] {
        assert_eq!(read(&mut smc, &sram, name), value);
    }
}

/// A reading at 0 on AC: a firmware's fixed `_BST` package, a pulled
/// battery, or a battery at its end; `critical` with the firmware's bit.
fn empty(critical: bool) -> PowerSnapshot {
    PowerSnapshot {
        ac_online: Some(true),
        battery: Some(BatteryState {
            status: Status::NotCharging,
            percent: Some(0),
            remaining_mah: Some(0),
            current_ma: Some(0),
            time_to_empty_min: None,
            critical,
            critical_bit: critical,
            ..discharging()
        }),
    }
}

#[test]
fn a_fall_to_0_without_the_critical_bit_shows_only_once_a_second_reading_confirms_it() {
    let (mut smc, sram) = with_battery();
    enable_notifications(&mut smc, &sram);
    let shows = |smc: &mut Smc, percent: u8, remaining: u16| {
        assert_eq!(read(smc, &sram, b"BUIC"), [percent]);
        assert_eq!(read(smc, &sram, b"B0UC"), remaining.to_le_bytes());
        assert_eq!(read(smc, &sram, b"B0RM"), remaining.to_le_bytes());
    };
    // One reading at 0 is held back: the keys keep the battery before it,
    // and only the AC adapter follows.
    smc.power(&empty(false), 10_000);
    assert!(smc.battery_held());
    shows(&mut smc, 73, 3_650);
    assert_eq!(read(&mut smc, &sram, b"CHCE"), [1]);
    assert_eq!(read(&mut smc, &sram, b"BCF0"), [0]);
    // The AC adapter's notice goes out; no battery one.
    assert_eq!(notifications(&mut smc), [0x18 | 0x7101_0101 << 32]);
    // A second confirms it: the battery is empty.
    smc.power(&empty(false), 40_000);
    assert!(!smc.battery_held());
    shows(&mut smc, 0, 0);
    // Once shown, 0 stays shown.
    smc.power(&empty(false), 70_000);
    assert!(!smc.battery_held());
    shows(&mut smc, 0, 0);

    // A reading back above 0 in between ends the doubt, and the next fall
    // waits for its own second reading.
    let (mut smc, sram) = with_battery();
    smc.power(&empty(false), 0);
    smc.power(&on_battery(), 30_000);
    assert!(!smc.battery_held());
    smc.power(&empty(false), 60_000);
    assert!(smc.battery_held());
    assert_eq!(read(&mut smc, &sram, b"BUIC"), [73]);
    // A remaining charge of 0 alone is a fall too.
    let (mut smc, sram) = with_battery();
    let drained = PowerSnapshot {
        battery: Some(BatteryState {
            remaining_mah: Some(0),
            ..discharging()
        }),
        ..on_battery()
    };
    smc.power(&drained, 0);
    assert!(smc.battery_held());
    assert_eq!(read(&mut smc, &sram, b"B0UC"), 3_650u16.to_le_bytes());
    // A critical from the low capacity alone is no word from the firmware:
    // it comes from the very 0 in doubt.
    let (mut smc, sram) = with_battery();
    let low = PowerSnapshot {
        ac_online: Some(false),
        battery: Some(BatteryState {
            status: Status::Discharging,
            critical: true,
            critical_bit: false,
            ..empty(false).battery.unwrap()
        }),
    };
    smc.power(&low, 0);
    assert!(smc.battery_held());
    assert_eq!(read(&mut smc, &sram, b"BCF0"), [0]);
}

#[test]
fn a_fall_to_0_with_the_firmwares_critical_bit_shows_at_once() {
    let (mut smc, sram) = with_battery();
    enable_notifications(&mut smc, &sram);
    let at = |smc: &mut Smc, name| read(smc, &sram, name);
    smc.power(&empty(true), 10_000);
    assert!(!smc.battery_held());
    assert_eq!(at(&mut smc, b"BUIC"), [0]);
    assert_eq!(at(&mut smc, b"B0UC"), [0, 0]);
    assert_eq!(at(&mut smc, b"BCF0"), [1]);
    // The AC adapter's notice and the battery turning critical.
    assert_eq!(
        notifications(&mut smc),
        [0x18 | 0x7101_0101 << 32, 0x18 | 0x7102_0000 << 32]
    );
}

#[test]
fn with_a_battery_each_distinct_missing_key_and_write_macos_makes_is_kept_once() {
    let (mut smc, sram) = with_battery();
    let asked = |asked, name: &[u8; 4], size, result| KeyRequest {
        asked,
        key: code(name),
        size,
        result,
    };
    // Missing keys read or asked about, once per key and kind.
    assert_eq!(result(&mut smc, READ, 8, b"BFS0"), KEY_NOT_FOUND);
    assert_eq!(result(&mut smc, READ, 2, b"BFS0"), KEY_NOT_FOUND);
    assert_eq!(result(&mut smc, KEY_INFO, 0, b"BFS0"), KEY_NOT_FOUND);
    // A key there is no question.
    read(&mut smc, &sram, b"B0UC");
    // Writes, once per key, size and result.
    sram.put(&[1]);
    assert_eq!(result(&mut smc, WRITE, 1, b"CH0C"), SUCCESS);
    assert_eq!(result(&mut smc, WRITE, 1, b"CH0C"), SUCCESS);
    assert_eq!(result(&mut smc, WRITE, 1, b"CHTE"), SIZE_MISMATCH);
    assert_eq!(result(&mut smc, WRITE, 1, b"B0UC"), NOT_WRITABLE);
    let requests: Vec<_> = core::iter::from_fn(|| smc.take_key_request()).collect();
    assert_eq!(
        requests,
        [
            asked(Asked::Read, b"BFS0", 8, KEY_NOT_FOUND),
            asked(Asked::Information, b"BFS0", 0, KEY_NOT_FOUND),
            asked(Asked::Write, b"CH0C", 1, SUCCESS),
            asked(Asked::Write, b"CHTE", 1, SIZE_MISMATCH),
            asked(Asked::Write, b"B0UC", 1, NOT_WRITABLE),
        ]
    );
    assert_eq!(
        requests.map_to_strings(),
        [
            "read SMC key BFS0 (8 bytes): not found (0x84)",
            "asked for SMC key BFS0's information: not found (0x84)",
            "wrote SMC key CH0C (1 byte): success",
            "wrote SMC key CHTE (1 byte): size mismatch (0x87)",
            "wrote SMC key B0UC (1 byte): not writable (0x86)",
        ]
    );
    // A key's bytes outside printable ASCII are shown as '?'.
    assert_eq!(
        result(&mut smc, READ, 1, &[b'k', 0, 0xff, b'Z']),
        KEY_NOT_FOUND
    );
    assert_eq!(
        smc.take_key_request().unwrap().to_string(),
        "read SMC key k??Z (1 byte): not found (0x84)"
    );
}

#[test]
fn the_requests_kept_are_bounded_and_the_bound_is_said() {
    let (mut smc, _) = with_battery();
    for number in 0..(REQUEST_LIMIT as u32 + 40) {
        let name = (0x5a00_0000 | number).to_be_bytes();
        assert_eq!(result(&mut smc, READ, 1, &name), KEY_NOT_FOUND);
    }
    let requests: Vec<_> = core::iter::from_fn(|| smc.take_key_request()).collect();
    assert_eq!(requests.len(), REQUEST_LIMIT + 1);
    assert_eq!(requests[REQUEST_LIMIT].asked, Asked::More);
    assert_eq!(
        requests[REQUEST_LIMIT].to_string(),
        "asked for more SMC keys than are said"
    );
    assert_eq!(smc.take_key_request(), None);
}

trait Strings {
    fn map_to_strings(&self) -> Vec<alloc::string::String>;
}

impl Strings for Vec<KeyRequest> {
    fn map_to_strings(&self) -> Vec<alloc::string::String> {
        use alloc::string::ToString;
        self.iter().map(ToString::to_string).collect()
    }
}

#[test]
fn latches_keep_writes_at_their_confirmed_sizes_only() {
    let (mut smc, sram) = with_battery();
    sram.put(&[1]);
    assert_eq!(result(&mut smc, WRITE, 1, b"CH0C"), SUCCESS);
    assert_eq!(read(&mut smc, &sram, b"CH0C"), [1]);
    sram.put(&80u32.to_le_bytes());
    assert_eq!(result(&mut smc, WRITE, 4, b"CHTE"), SUCCESS);
    assert_eq!(read(&mut smc, &sram, b"CHTE"), 80u32.to_le_bytes());
    // A 1-byte form of a 4-byte latch is refused as the wrong size.
    assert_eq!(result(&mut smc, WRITE, 1, b"CHTE"), SIZE_MISMATCH);
    assert_eq!(result(&mut smc, WRITE, 1, b"bfD0"), SIZE_MISMATCH);
    sram.put(&0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(result(&mut smc, WRITE, 8, b"BDFU"), SUCCESS);
    assert_eq!(
        read(&mut smc, &sram, b"BDFU"),
        0x1122_3344_5566_7788u64.to_le_bytes()
    );
    // The readings are the host's: not writable.
    for name in [b"B0UC", b"BPCC", b"MSLD", b"CHCE"] {
        assert_eq!(result(&mut smc, WRITE, 1, name), NOT_WRITABLE);
    }
    // A latch keeps its value across host readings.
    smc.power(&charging(), 0);
    assert_eq!(read(&mut smc, &sram, b"CH0C"), [1]);
}

#[test]
fn ac_changes_and_a_battery_turning_critical_notify_once_enabled_and_no_closer_than_their_spacing()
{
    // The last byte is the AC adapter's new state.
    const EXTERNAL_POWER: u64 = 0x18 | 0x7101_0100 << 32;
    const PLUGGED: u64 = 0x18 | 0x7101_0101 << 32;
    const BATTERY_STATE: u64 = 0x18 | 0x7102_0000 << 32;
    let critical = |critical| PowerSnapshot {
        battery: Some(BatteryState {
            critical,
            ..discharging()
        }),
        ..on_battery()
    };
    let (mut smc, sram) = with_battery();
    // Before the AP enables notifications a change only moves the values,
    // and nothing waits for later.
    assert_eq!(smc.power(&charging(), 1_000), None);
    assert_eq!(read(&mut smc, &sram, b"CHCE"), [1]);
    enable_notifications(&mut smc, &sram);
    assert!(notifications(&mut smc).is_empty());
    assert_eq!(smc.power_due(60_000), None);

    // Unplugged: AC change (0x7101) triggers a full poll; no redundant 0x7102.
    assert_eq!(smc.power(&on_battery(), 10_000), None);
    assert_eq!(notifications(&mut smc), [EXTERNAL_POWER]);
    // Voltage, current and time drift alone send nothing.
    let drift = PowerSnapshot {
        battery: Some(BatteryState {
            voltage_mv: Some(15_700),
            current_ma: Some(-2_700),
            time_to_empty_min: Some(80),
            ..discharging()
        }),
        ..on_battery()
    };
    assert_eq!(smc.power(&drift, 10_100), None);
    assert!(notifications(&mut smc).is_empty());
    // A percent step sends 0x7102 immediately (first battery-state notice).
    let step = PowerSnapshot {
        battery: Some(BatteryState {
            percent: Some(72),
            ..discharging()
        }),
        ..on_battery()
    };
    assert_eq!(smc.power(&step, 10_200), None);
    assert_eq!(read(&mut smc, &sram, b"BUIC"), [72]);
    assert_eq!(notifications(&mut smc), [BATTERY_STATE]);
    // Turning critical sends 0x7102 once spaced past 10_200 + 5 s.
    assert_eq!(smc.power(&critical(true), 25_000), None);
    assert_eq!(notifications(&mut smc), [BATTERY_STATE]);
    // Staying critical, or no longer critical, is not.
    assert_eq!(smc.power(&critical(true), 26_000), None);
    assert_eq!(smc.power(&critical(false), 27_000), None);
    assert!(notifications(&mut smc).is_empty());
    // Critical again 3 s after the last notice waits for its 5 s spacing.
    let spaced = 25_000 + SPACING_MILLIS[1];
    assert_eq!(smc.power(&critical(true), 28_000), Some(spaced));
    assert_eq!(smc.power_due(spaced - 1), Some(spaced));
    assert!(notifications(&mut smc).is_empty());
    assert_eq!(smc.power_due(spaced), None);
    assert_eq!(notifications(&mut smc), [BATTERY_STATE]);

    // Plugged in, then out 0.5 s later: the second AC notice waits for its
    // 1 s spacing, and two changes in the wait go out as one.
    let (mut smc, sram) = with_battery();
    enable_notifications(&mut smc, &sram);
    assert_eq!(smc.power(&charging(), 20_000), None);
    assert_eq!(notifications(&mut smc), [PLUGGED]);
    let ac_due = 20_000 + SPACING_MILLIS[0];
    assert_eq!(smc.power(&on_battery(), 20_500), Some(ac_due));
    assert_eq!(smc.power(&charging(), 20_700), Some(ac_due));
    assert!(notifications(&mut smc).is_empty());
    // The one notice carries the state when it goes out.
    assert_eq!(smc.power_due(ac_due), None);
    assert_eq!(notifications(&mut smc), [PLUGGED]);
    assert_eq!(smc.power(&on_battery(), 30_000), None);
    assert_eq!(notifications(&mut smc), [EXTERNAL_POWER]);
}

#[test]
fn a_change_while_the_soc_sleeps_waits_for_its_wake() {
    let (smc, sram) = with_battery();
    let mut smc = smc.with_wake_bits(WakeBits {
        power_button: Some(0),
        rtc: None,
    });
    enable_notifications(&mut smc, &sram);
    sram.put(&code(b"slpa").to_le_bytes());
    assert_eq!(result(&mut smc, WRITE, 4, b"MBSE"), SUCCESS);
    smc.enter_sleep();
    assert_eq!(
        smc.power(&charging(), 30_000),
        Some(30_000 + ASLEEP_RETRY_MILLIS)
    );
    assert!(notifications(&mut smc).is_empty());
    assert_eq!(smc.power_due(31_000), Some(31_000 + ASLEEP_RETRY_MILLIS));
    assert!(notifications(&mut smc).is_empty());
    smc.wake(WakeSource::PowerButton);
    assert_eq!(smc.power_due(32_000), None);
    assert_eq!(notifications(&mut smc), [0x18 | 0x7101_0101 << 32]);
}

#[test]
fn low_power_emergency_mode_powers_off_a_machine_with_a_battery() {
    let (mut smc, sram) = with_battery();
    sram.put(&code(b"lpem").to_le_bytes());
    assert_eq!(result(&mut smc, WRITE, 4, b"MBSE"), SUCCESS);
    let off = smc.take_transition().unwrap();
    assert_eq!((off.device, off.transition), ("smc", Transition::PowerOff));
}

#[test]
fn a_battery_joins_the_table_once_with_a_reading_and_counts_with_the_rtc_key() {
    use crate::pmu::{RtcClock, RtcEpoch};
    let (mut smc, _) = mac_mini();
    // No reading of a battery: no battery.
    let none = PowerSnapshot {
        ac_online: Some(true),
        battery: None,
    };
    assert!(smc.add_battery(&none).is_err());
    assert_eq!(smc.keys.len() as u32, MAC_MINI_KEYS);
    let clock = RtcClock::new(RtcEpoch {
        counter: 0,
        ticks: 0,
    })
    .unwrap();
    smc.bind_rtc(clock.clone(), RtcKeyProfile::Hex48Little)
        .unwrap();
    smc.add_battery(&PowerSnapshot::synthetic(80, TestState::Charging))
        .unwrap();
    assert!(smc.add_battery(&on_battery()).is_err());
    let count = MAC_MINI_KEYS + 1 + TABLE.len() as u32;
    assert_eq!(smc.value(KEY_COUNT), Some(&count.to_be_bytes()[..]));
    // Every index names a key, the RTC's included, then the range ends.
    let names: Vec<u32> = (0..count as usize)
        .map(|index| smc.key_by_index(index).unwrap())
        .collect();
    assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(names.contains(&rtc::KEY));
    assert_eq!(smc.key_by_index(count as usize), None);
    // The battery first, then the RTC.
    let (mut smc, _) = mac_mini();
    smc.add_battery(&on_battery()).unwrap();
    smc.bind_rtc(clock, RtcKeyProfile::Hex48Little).unwrap();
    assert_eq!(smc.value(KEY_COUNT), Some(&count.to_be_bytes()[..]));
    // A board key with a battery key's name is refused.
    let sram = Sram::default();
    let mut clash = Smc::new(sram, BASE, vec![(code(b"B0UC"), Key::gpio())]).unwrap();
    assert!(clash.add_battery(&on_battery()).is_err());
    assert!(clash.battery.is_none());
}

//! The SMC's battery: the keys macOS's battery driver reads, answered from
//! the host's power snapshot ([`PowerSnapshot`]), and the power
//! notifications its changes send. Only an SMC given a battery
//! ([`super::Smc::add_battery`]) has them; any other answers every one of
//! them KEY_NOT_FOUND, as the Mac mini's does.
//!
//! Evidence (26B123 `kernelcache.release.mac14g`, the one kernel J413, J473
//! and J493 boot; KC file offsets). `AppleSmartBatteryManager` matches
//! `IOProviderClass` `AppleSMC` and nothing else, so it starts on every
//! Apple-silicon Mac, the Mac mini included. At the SMC's arrival
//! `AppleSmartBattery::smcNotifierHandler` (0x2e5e670) asks GET_KEY_INFO for
//! each command's key and keeps its size; a key the SMC answers
//! KEY_NOT_FOUND becomes `NOOP` ("SMC key ... not supported"), not an error.
//! It then reads `BPCC`, 2 bytes taken as a little-endian word whose high
//! byte is the number of battery packs and low byte the number of chargers
//! (0x2e5e918..0x2e5e980): the battery is installed when packs is nonzero
//! (0x2e5ece0). `_smcKeyInfo` (0x2e69078) decodes a key by its declared
//! type: an integer of up to 8 bytes, signed when the type begins with `s`,
//! `flt `, `ioft`, or a blob past 8 bytes. So each key here is declared with
//! the type Linux's `macsmc-power` (Asahi) reads on real Apple-silicon
//! laptops, where it names one, and macOS follows the declaration.
//!
//! The command keys (`getSmcKeyForCommand::keyTable`, 0x760798; Smart
//! Battery command numbers): `B0AV` voltage (0x09, mV), `B0AC` current
//! (0x0a, mA, negative while discharging), `B0IV` average current (0x0b;
//! the host reports no average, so the current), `B0UC` remaining capacity
//! (0x0f) and `B0CM` full charge capacity (0x10), both mAh: macOS takes
//! these two from `B0UC`/`B0CM`, not Asahi's `B0RM`/`B0FC`. `B0TE`/`B0TF`
//! average time to empty and to full (0x12, 0x13, minutes, 0xffff for
//! none), `B0CT` cycle count (0x17, 0 when the host has none), `BMDN`
//! device name (0x21) and `BMSN` serial (0x76) as 32-byte `ch8*` strings,
//! `CHSC` charger status (0x01, 1 byte, `AppleSMCChargerFunction::
//! getChargerState`; 1 while charging), `CHCE` external power connected
//! (0x100), `CHCC` charge capable (0x200, 1 byte, `externalConnectedTimeout`),
//! `BSFC` fully charged (0x300) and `BCF0` critical (0x400). Read at a fixed
//! size: `BPCC` (one pack, no charger: no `AppleChargerData` key is here),
//! `AC-N` adapters connected and `AC-W` the active one's port, 1-based, as
//! `readAdapterInfo` reads them (1 byte each). For the registry's
//! `BatteryData`: `BUIC` the percentage, `B0RM` remaining, `B0FC` full charge
//! and `B0DC` design capacity, mAh. `B0RM` is little-endian like the rest:
//! Linux's `macsmc-power` swaps it only on firmware older than macOS 27's,
//! which it tells by a 4-byte `BCF0`, and this `BCF0` is macOS 27's 1 byte.
//! Latches the battery driver and powerd write at these confirmed sizes,
//! kept and read back, changing nothing on the host: `CH0C`/`CH0I` charge
//! and connect inhibit, `D0IG`, `UB0C`, `BSCL` the shipping charge limit (1
//! byte), `CHTE`/`bfD0` the charge limit and `WAFC` (4 bytes), `BDFU` date
//! of first use and `UB0T` (8 bytes). Left out, so their readers skip them:
//! `D3Au` (the MagSafe charger utility stops without it), `CHNC`, `B0CU`,
//! `BCFW`, `CH0V`, `CHAS`, `B0BL`, `CHCR`, `BMDA`, the adapter detail keys
//! and the diagnostics tables.
//!
//! A reading that falls to 0, a percentage or remaining charge of 0 where the
//! keys showed more ([`BatteryState::reads_empty`]), without the firmware's
//! `_BST` critical bit, is held back until the next reading confirms it: the
//! keys keep the battery before it, and only the AC adapter follows. One
//! such reading alone may be a firmware's fixed `_BST` package or a battery
//! pulled with no notification, and macOS shuts down on a battery it reads
//! as empty. With the bit it shows at once; a critical from the low capacity
//! alone does not count, as it comes from the very 0 in doubt.
//!
//! `MSLD` is the lid: 1 byte, 1 closed and 0 open
//! (`AppleSMCPMU::_sendLidStateToRootDomainGated`, 0x2db9590). AppleSMCPMU
//! reads it only on a board whose `smc-pmu` has `has_lid_open_sensor`,
//! which J473's has not; it reads 0, open, for any other reader.
//!
//! Notifications (event-name table at 0x12d79b8, indexed by subclass):
//! `AppleSmartBattery::smcNotifierHandler` registers `AppleSmartBattery::
//! messageSMC` (0x2e6e610) on `smcPowerStateNotifySymbol` (`pow`, class 0x71).
//! `messageSMC` (0x2e6e94c..0x2e6e9a8) triggers a full poll
//! (`pollBatteryState(2)`) on subclass 1 (`pow.ExternalPowerChange`, 0x7101)
//! and a user-visible poll (`pollBatteryState(4)`) on subclass 2
//! (`pow.BatteryStateChange`, 0x7102). `AppleSmartBattery` has no periodic
//! polling timer, so 0x7101 goes out when the AC adapter comes or goes and
//! 0x7102 goes out when percentage, charging status or the critical flag
//! changes. Their data bytes are those Asahi saw (`0x710101xx`, with the AC
//! adapter's new state as `xx`, and `0x71020000`). Each kind goes out at most
//! once a [`SPACING_MILLIS`] apart, a change in between waiting for the
//! spacing to end, and only once the AP has enabled notifications, as every
//! other: a change before that only moves the values, which the AP reads when
//! it starts. While the SoC sleeps a change waits for it to wake.
//!
//! Endianness: `AppleSmartBattery::_smcReadKey` (0x2e653a0) calls
//! `AppleSMCFamily::smcReadKeyHostEndian` (vtable +0x890, 0x2dcfe20), which
//! reverses any 2..=8-byte value unless `keyAttributes` bit 2
//! ([`LITTLE_ENDIAN`], 0x04) is set (0x2dcfed0..0x2dcff10). Every 2..=8-byte
//! battery key here is stored little-endian and carries [`LITTLE_ENDIAN`];
//! without it `BPCC` (`[0x00, 0x01]`) is swapped to `0x0001` (0 packs, 1
//! charger), hiding the battery from macOS and pinning `ExternalConnected` on.
use super::{Key, LITTLE_ENDIAN, READABLE, WRITABLE, code, event};
use alloc::{vec, vec::Vec};
use stela_drivers::platform::power_snapshot::{BatteryState, PowerSnapshot, Status, Summary};

/// Battery packs in the high byte, chargers in the low.
pub(super) const PACK_COUNT: u32 = code(b"BPCC");
const VOLTAGE: u32 = code(b"B0AV");
const CURRENT: u32 = code(b"B0AC");
const AVERAGE_CURRENT: u32 = code(b"B0IV");
const REMAINING: u32 = code(b"B0UC");
const FULL_CHARGE: u32 = code(b"B0CM");
const TIME_TO_EMPTY: u32 = code(b"B0TE");
const TIME_TO_FULL: u32 = code(b"B0TF");
const CYCLE_COUNT: u32 = code(b"B0CT");
const DEVICE_NAME: u32 = code(b"BMDN");
const SERIAL: u32 = code(b"BMSN");
const CHARGER_STATUS: u32 = code(b"CHSC");
const EXTERNAL_CONNECTED: u32 = code(b"CHCE");
const CHARGE_CAPABLE: u32 = code(b"CHCC");
const FULLY_CHARGED: u32 = code(b"BSFC");
const CRITICAL: u32 = code(b"BCF0");
const ADAPTERS: u32 = code(b"AC-N");
const ACTIVE_ADAPTER: u32 = code(b"AC-W");
const PERCENT: u32 = code(b"BUIC");
const REMAINING_REGISTRY: u32 = code(b"B0RM");
const FULL_CHARGE_REGISTRY: u32 = code(b"B0FC");
const DESIGN_CAPACITY: u32 = code(b"B0DC");
/// The lid switch, 0 open.
pub(super) const LID_CLOSED: u32 = code(b"MSLD");

/// The latches: name, type and size.
const LATCHES: [(&[u8; 4], &[u8; 4], usize); 10] = [
    (b"CH0C", b"ui8 ", 1),
    (b"CH0I", b"ui8 ", 1),
    (b"D0IG", b"ui8 ", 1),
    (b"UB0C", b"ui8 ", 1),
    (b"BSCL", b"ui8 ", 1),
    (b"CHTE", b"ui32", 4),
    (b"bfD0", b"ui32", 4),
    (b"WAFC", b"ui32", 4),
    (b"BDFU", b"ui64", 8),
    (b"UB0T", b"ui64", 8),
];

/// The keys that show the reading, with their types, in [`values`]'s order.
const READINGS: [(u32, &[u8; 4]); 21] = [
    (VOLTAGE, b"ui16"),
    (CURRENT, b"si16"),
    (AVERAGE_CURRENT, b"si16"),
    (REMAINING, b"ui16"),
    (FULL_CHARGE, b"ui16"),
    (TIME_TO_EMPTY, b"ui16"),
    (TIME_TO_FULL, b"ui16"),
    (CYCLE_COUNT, b"ui16"),
    (DEVICE_NAME, b"ch8*"),
    (SERIAL, b"ch8*"),
    (CHARGER_STATUS, b"ui8 "),
    (EXTERNAL_CONNECTED, b"flag"),
    (CHARGE_CAPABLE, b"ui8 "),
    (FULLY_CHARGED, b"flag"),
    (CRITICAL, b"flag"),
    (ADAPTERS, b"ui8 "),
    (ACTIVE_ADAPTER, b"ui8 "),
    (PERCENT, b"ui8 "),
    (REMAINING_REGISTRY, b"ui16"),
    (FULL_CHARGE_REGISTRY, b"ui16"),
    (DESIGN_CAPACITY, b"ui16"),
];

/// One pack, no charger.
const PACKS: u16 = 0x0100;
/// `B0TE`/`B0TF` with no estimate; a known time is held below it.
const NO_TIME: u16 = 0xffff;

/// Notification classes, subclasses and the order they go out in.
const POWER_STATE: u8 = 0x71;
const EXTERNAL_POWER: usize = 0;
const BATTERY_STATE: usize = 1;
/// `pow.ExternalPowerChange`'s last byte is the AC adapter's new state, 1
/// online, filled in as it goes out.
const EVENTS: [u32; 2] = [
    event(POWER_STATE, 0x01, 0x01, 0x00),
    event(POWER_STATE, 0x02, 0x00, 0x00),
];
/// The least time between two notifications of a kind.
pub(super) const SPACING_MILLIS: [u64; 2] = [1_000, 5_000];
/// How soon a change that waits for the SoC to wake is looked at again.
pub(super) const ASLEEP_RETRY_MILLIS: u64 = 1_000;

/// The battery's keys, with `snapshot`'s values.
pub(super) fn keys(snapshot: &PowerSnapshot) -> Vec<(u32, Key)> {
    // `AppleSMCFamily::smcReadKeyHostEndian` swaps 2..=8-byte values unless
    // `LITTLE_ENDIAN` (bit 2) is set in `keyAttributes`. Every multi-byte
    // integer key here is stored little-endian, so mark 2..=8-byte values.
    let endian = |bytes: usize| {
        if (2..=8).contains(&bytes) {
            LITTLE_ENDIAN
        } else {
            0
        }
    };
    let fixed = |kind: &[u8; 4], value: Vec<u8>| {
        let flags = READABLE | endian(value.len());
        Key {
            kind: code(kind),
            flags,
            value,
        }
    };
    let mut keys: Vec<(u32, Key)> = READINGS
        .iter()
        .zip(values(snapshot))
        .map(|(&(name, kind), value)| (name, fixed(kind, value)))
        .collect();
    keys.push((PACK_COUNT, fixed(b"ui16", PACKS.to_le_bytes().to_vec())));
    keys.push((LID_CLOSED, fixed(b"ui8 ", vec![0])));
    keys.extend(LATCHES.iter().map(|&(name, kind, bytes)| {
        (
            code(name),
            Key::new(kind, READABLE | WRITABLE | endian(bytes), bytes),
        )
    }));
    keys
}

/// The reading's keys' values, in [`READINGS`]' order: integers
/// little-endian and held at their type's ends, unknown values 0, and no
/// time estimate [`NO_TIME`].
fn values(shown: &PowerSnapshot) -> [Vec<u8>; READINGS.len()] {
    let battery = shown.battery.as_ref();
    let unsigned = |field: fn(&BatteryState) -> Option<u32>| {
        let value = battery.and_then(field).unwrap_or(0);
        u16::try_from(value).unwrap_or(u16::MAX)
    };
    let time = |field: fn(&BatteryState) -> Option<u32>| {
        battery.and_then(field).map_or(NO_TIME, |minutes| {
            minutes.min(u32::from(NO_TIME - 1)) as u16
        })
    };
    let current = battery
        .and_then(|battery| battery.current_ma)
        .unwrap_or(0)
        .clamp(i16::MIN.into(), i16::MAX.into()) as i16;
    let flag = |value: bool| vec![u8::from(value)];
    let status = battery.map(|battery| battery.status);
    let ac = shown.ac_online == Some(true);
    let remaining = unsigned(|battery| battery.remaining_mah);
    let full = unsigned(|battery| battery.full_mah);
    let name = |name: fn(&BatteryState) -> &[u8; 32]| {
        battery.map_or(vec![0; 32], |battery| name(battery).to_vec())
    };
    [
        unsigned(|battery| battery.voltage_mv)
            .to_le_bytes()
            .to_vec(),
        current.to_le_bytes().to_vec(),
        current.to_le_bytes().to_vec(),
        remaining.to_le_bytes().to_vec(),
        full.to_le_bytes().to_vec(),
        time(|battery| battery.time_to_empty_min)
            .to_le_bytes()
            .to_vec(),
        time(|battery| battery.time_to_full_min)
            .to_le_bytes()
            .to_vec(),
        unsigned(|battery| battery.cycle_count)
            .to_le_bytes()
            .to_vec(),
        name(|battery| battery.model.padded()),
        name(|battery| battery.serial.padded()),
        flag(status == Some(Status::Charging)),
        flag(ac),
        flag(ac),
        flag(status == Some(Status::Full)),
        flag(battery.is_some_and(|battery| battery.critical)),
        flag(ac),
        flag(ac),
        vec![
            battery
                .and_then(|battery| battery.percent)
                .unwrap_or(0)
                .min(100),
        ],
        remaining.to_le_bytes().to_vec(),
        full.to_le_bytes().to_vec(),
        unsigned(|battery| battery.design_mah)
            .to_le_bytes()
            .to_vec(),
    ]
}

/// `next` with each value it lost taken from `before`; its times stay its
/// own, and a current only from a reading of the same status.
fn merge(next: BatteryState, before: BatteryState) -> BatteryState {
    let same_status = before.status == next.status;
    BatteryState {
        percent: next.percent.or(before.percent),
        remaining_mah: next.remaining_mah.or(before.remaining_mah),
        full_mah: next.full_mah.or(before.full_mah),
        design_mah: next.design_mah.or(before.design_mah),
        warning_mah: next.warning_mah.or(before.warning_mah),
        low_mah: next.low_mah.or(before.low_mah),
        voltage_mv: next.voltage_mv.or(before.voltage_mv),
        current_ma: next
            .current_ma
            .or(before.current_ma.filter(|_| same_status)),
        power_mw: next.power_mw.or(before.power_mw.filter(|_| same_status)),
        cycle_count: next.cycle_count.or(before.cycle_count),
        ..next
    }
}

/// What the SMC shows and what it last told the AP.
pub(super) struct Battery {
    /// What the keys show: the latest reading, each unknown value kept from
    /// the readings before it.
    shown: PowerSnapshot,
    /// The latest reading fell to 0 without the firmware's critical bit, and
    /// the keys kept the battery before it until another confirms it.
    held: bool,
    /// The summary the last change was measured against.
    measured: Summary,
    /// When each notification last went out.
    sent: [Option<u64>; 2],
    /// A notification of each kind waits.
    pending: [bool; 2],
}

impl Battery {
    pub(super) fn new(snapshot: &PowerSnapshot) -> Self {
        Self {
            shown: *snapshot,
            held: false,
            measured: snapshot.summary(),
            sent: [None; 2],
            pending: [false; 2],
        }
    }

    /// A new reading: the values the keys take, by key. A fall to 0 without
    /// the firmware's critical bit keeps the battery before it, the first
    /// time ([`Self::held`]). A change in the AC adapter, or the battery
    /// turning critical, makes its notification wait ([`Self::due`]).
    pub(super) fn update(&mut self, snapshot: &PowerSnapshot) -> Vec<(u32, Vec<u8>)> {
        let before = self.shown;
        let falls = snapshot.battery.is_some_and(|next| {
            next.reads_empty()
                && !next.critical_bit
                && before.battery.is_some_and(|shown| !shown.reads_empty())
        });
        // The second fall in a row confirms the first.
        self.held = falls && !self.held;
        let next = snapshot.battery.filter(|_| !self.held);
        self.shown = PowerSnapshot {
            ac_online: snapshot.ac_online.or(before.ac_online),
            battery: match (next, before.battery) {
                (Some(next), Some(before)) => Some(merge(next, before)),
                (next, before) => next.or(before),
            },
        };
        let summary = self.shown.summary();
        let measured = self.measured;
        let ac_changed = summary.ac_online != measured.ac_online;
        self.pending[EXTERNAL_POWER] |= ac_changed;
        // `0x7101` already triggers a full poll (`pollBatteryState(2)`), so
        // send `0x7102` (`pollBatteryState(4)`) when turning critical or when
        // percent/status changes without an AC transition.
        self.pending[BATTERY_STATE] |= (summary.critical && !measured.critical)
            || (!ac_changed
                && (summary.percent != measured.percent || summary.status != measured.status));
        self.measured = summary;
        READINGS
            .iter()
            .map(|&(name, _)| name)
            .zip(values(&self.shown))
            .collect()
    }

    /// The latest reading fell to 0 without the firmware's critical bit, and
    /// the keys show the battery before it until the next reading confirms
    /// it.
    pub(super) fn held(&self) -> bool {
        self.held
    }

    /// The notifications due at `now`, in order, given whether the AP takes
    /// them now, and when the next waiting one is due.
    pub(super) fn due(&mut self, now: u64, enabled: bool, asleep: bool) -> (Vec<u32>, Option<u64>) {
        if !enabled {
            // The AP reads the values when it starts.
            self.pending = [false; 2];
            return (Vec::new(), None);
        }
        let mut events = Vec::new();
        let mut next: Option<u64> = None;
        for kind in [EXTERNAL_POWER, BATTERY_STATE] {
            if !self.pending[kind] {
                continue;
            }
            let at = match self.sent[kind] {
                _ if asleep => now.saturating_add(ASLEEP_RETRY_MILLIS),
                Some(sent) => sent.saturating_add(SPACING_MILLIS[kind]),
                None => now,
            };
            if !asleep && now >= at {
                let ac = u32::from(self.shown.ac_online == Some(true));
                events.push(match kind {
                    EXTERNAL_POWER => EVENTS[kind] | ac,
                    _ => EVENTS[kind],
                });
                self.sent[kind] = Some(now);
                self.pending[kind] = false;
            } else {
                next = Some(next.map_or(at, |next| next.min(at)));
            }
        }
        (events, next)
    }
}

#[cfg(test)]
mod tests;

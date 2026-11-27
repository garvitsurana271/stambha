//! `stela.cfg`'s system-mode options: one typed record, the one parser
//! `stela.efi`'s loader and engine read it with, and the one serializer
//! `stela` writes it with. The option line is whitespace-separated
//! words starting with `--system`; each option is a flag or a flag and one
//! value. The spellings are part of the setup/mount contract
//! (`stela_loader::mount_interface::OPTIONS_REVISION`).
use crate::Result;
use alloc::{string::String, vec::Vec};
use core::fmt;
use stela_contracts::refuse;
pub use stela_contracts::uuid::Uuid;
use stela_loader::{
    boot_selection::{self, BootVolume},
    handoff::BootCommand,
    mount_interface, recovery,
};
use stela_runtime::pc::{gpt::Guid, storage::Target};

mod error;
mod parse;
mod validate;

pub use error::{Constraint, Error, GuidArgument, TargetArgument};

/// Apple T8112 DRAM base (Asahi Linux T8112 notes; the DeviceTree `/memory`).
pub const DRAM_BASE: u64 = 0x8_0000_0000;
const LARGE: u64 = 2 * 1024 * 1024;

pub const SYSTEM: &str = "--system";
pub const INSTALL: &str = mount_interface::INSTALL_OPTION;
pub const INSTALL_SOURCE: &str = "--install-source";
/// The install medium's read-ahead, in 1 MiB chunks kept ahead of its
/// reader (`--medium-read-ahead N`): 0 reads it only when asked, as before
/// the read-ahead, for an A/B of one image. Named apart from install mode's
/// own `--install-mode` and `--install-build` ([`crate::install_mode`]).
pub const MEDIUM_READ_AHEAD: &str = "--medium-read-ahead";
/// The most chunks `--medium-read-ahead` keeps ahead: 16 MiB of memory.
pub const MAX_MEDIUM_READ_AHEAD: usize = 16;
pub const VERIFY_ON_READ: &str = "--verify-on-read";
pub const UPDATE_RESTORE: &str = mount_interface::UPDATE_RESTORE_OPTION;
pub const EXTERNAL_DISKS: &str = "--external-disks";
pub const NATIVE_CORES: &str = "--native-cores";
pub const GUEST_PES: &str = "--guest-pes";
/// The board's code window in MiB (`--code-window MIB`), in place of the
/// one sized from the host's RAM (`host_memory::with_window`).
pub const CODE_WINDOW: &str = "--code-window";
/// Issue no indirect branch prediction barrier at guest context switches
/// (`--no-ibpb`): see [`System::no_ibpb`].
pub const NO_IBPB: &str = "--no-ibpb";
/// The latest a busy PE's timer interrupt comes, in microseconds
/// (`--timer-delay-us N`): see [`System::timer_delay`].
pub const TIMER_DELAY: &str = "--timer-delay-us";
/// [`TIMER_DELAY`]'s bounds.
pub const TIMER_DELAY_MICROS: core::ops::RangeInclusive<u64> = 100..=100_000;
/// The size a GPU's display is taken in (`--display-size WIDTHxHEIGHT`), in
/// place of the monitor's preferred mode: for a capture device that cannot
/// take the mode its EDID prefers.
pub const DISPLAY_SIZE: &str = "--display-size";
pub const MAINTENANCE_WRITE: &str = "--maintenance-write";
/// Host kernels for AMX register operations (`--amx-native on|off|off:OPS`):
/// on by default; off leaves every one to the reference model, `off:` and
/// operations' mnemonics, comma separated, those ([`AmxModel`]).
pub const AMX_NATIVE: &str = "--amx-native";

/// [`AMX_NATIVE`]'s value: the AMX register operations the reference model
/// completes alone, which no host kernel then touches, by number (bit n:
/// bits 9:5 of the word equal to n). `on` is none, `off` every one and
/// `off:fma16,vecfp` those named, so that a guest misbehaving under host
/// kernels can be narrowed to an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmxModel(pub u32);

impl AmxModel {
    /// `on`: host kernels complete every operation they cover.
    pub const NONE: Self = Self(0);
    /// `off`: the model completes every operation.
    pub const ALL: Self = Self(u32::MAX);

    /// The register operations blocks complete through a routine, in
    /// number order.
    fn operations() -> impl Iterator<Item = stela_compiler::amx::AmxOperation> {
        stela_compiler::amx::AmxOperation::ALL
            .into_iter()
            .filter(|&operation| stela_compiler::x86_64::amx_routine::calls(operation))
    }

    /// `on`, `off`, or `off:` and register operations' mnemonics (corsix's,
    /// such as `fma32`), comma separated; `None` for anything else.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "on" => Some(Self::NONE),
            "off" => Some(Self::ALL),
            _ => text
                .strip_prefix("off:")?
                .split(',')
                .try_fold(0, |bits, name| {
                    let operation =
                        Self::operations().find(|operation| operation.mnemonic() == name)?;
                    Some(bits | 1 << operation.encoding().0)
                })
                .map(Self),
        }
    }
}

impl fmt::Display for AmxModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NONE => f.write_str("on"),
            Self::ALL => f.write_str("off"),
            Self(bits) => {
                f.write_str("off")?;
                let mut separator = ':';
                for operation in
                    Self::operations().filter(|operation| bits >> operation.encoding().0 & 1 != 0)
                {
                    write!(f, "{separator}{}", operation.mnemonic())?;
                    separator = ',';
                }
                Ok(())
            }
        }
    }
}
/// Boots the installed system to its single-user shell.
pub const SINGLE_USER: &str = "--single-user";
/// Keeps the newest presented frame at one logged address.
pub const SCANOUT_MIRROR: &str = "--scanout-mirror";
pub const WIFI: &str = "--wifi";
pub const WIFI_KEY: &str = "--wifi-key";
pub const WIFI_COUNTRY: &str = "--wifi-country";
/// The saved network to prefer this boot over the `--wifi` one, as the
/// startup menu's Wi-Fi page chose it (`choice::wifi`).
pub const WIFI_PREFER: &str = "--wifi-prefer";
pub const USB4_APPROVE: &str = "--usb4-approve";
pub const BLUETOOTH_TRACE: &str = "--bluetooth-trace";
pub const BLUETOOTH_LEND: &str = "--bluetooth-lend";
/// The ESP file `--wifi` reads its key from without `--wifi-key`.
pub const DEFAULT_WIFI_KEY: &str = "\\EFI\\stela\\wifi.key";
/// The saved networks a boot with `--wifi` also joins when its network is
/// not in range (`wifi_saved`); none when the file is absent.
pub const WIFI_SAVED: &str = "\\EFI\\stela\\wifi.saved";
/// What the startup menu's Wi-Fi page writes first when it changes
/// [`WIFI_SAVED`], whose rewrite deletes the file before writing it: it
/// stands for that file when a write it could not finish left it absent
/// (`wifi_saved::current`).
pub const WIFI_SAVED_NEW: &str = "\\EFI\\stela\\wifi.saved.new";
/// IEEE 802.11 SSIDs are 1 to 32 octets.
const SSID_BYTES: core::ops::RangeInclusive<usize> = 1..=32;
pub const IPV4: &str = "--ipv4";
pub const IPV4_GATEWAY: &str = "--ipv4-gateway";
pub const DNS: &str = "--dns";
/// The most `--dns` servers, as glibc's resolver keeps (`MAXNS`).
pub const MAX_DNS_SERVERS: usize = 3;
pub const BATTERY: &str = "--battery";
pub const TEST_BATTERY: &str = "--test-battery";

pub use stela_driver_base::platform::power_snapshot::TestState;

/// The battery the guest's SMC presents (`--battery`, `--test-battery`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Battery {
    /// The host's first ACPI battery and its AC adapter.
    Host,
    /// A synthetic battery, for a machine with none such as a virtual one:
    /// `PERCENT,STATE`, 1 to 100 and `charging`, `discharging` (from
    /// [`MIN_DISCHARGING_PERCENT`]) or `full`, which is only at 100. At 0 the
    /// SMC takes no battery, as macOS shuts down on one it reads as empty.
    Test { percent: u8, state: TestState },
}

/// The least percentage a `--test-battery` discharges at.
pub const MIN_DISCHARGING_PERCENT: u8 = 5;

impl Battery {
    fn parse_test(word: &str) -> Option<Self> {
        let (percent, state) = word.split_once(',')?;
        let percent: u8 = percent
            .parse()
            .ok()
            .filter(|percent| (1..=100).contains(percent))?;
        let state = match state {
            "charging" => TestState::Charging,
            // Below 5% the discharging test battery is at or near its 3%
            // low capacity, critical as it attaches: macOS would shut down.
            "discharging" if percent >= MIN_DISCHARGING_PERCENT => TestState::Discharging,
            "full" if percent == 100 => TestState::Full,
            _ => return None,
        };
        Some(Self::Test { percent, state })
    }
}

/// A `--test-battery` value, as it is written.
struct TestBattery(u8, TestState);

impl fmt::Display for TestBattery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match self.1 {
            TestState::Charging => "charging",
            TestState::Discharging => "discharging",
            TestState::Full => "full",
        };
        write!(f, "{},{state}", self.0)
    }
}

/// What the host does with its lid (`--lid`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Lid {
    /// Nothing, the default, though a laptop takes [`Self::Method`]
    /// unasked ([`crate::laptop`]): Linux's kernel only reports the lid, its
    /// userspace decides, and a wrong `_LID` reading is common enough that
    /// Linux keeps DMI quirks for it.
    #[default]
    Ignore,
    /// A close the firmware notifies darkens a display on built-in panels
    /// alone, and the next lid notification or built-in input lights it
    /// ([`crate::lid_panel`]).
    Method,
}

impl Lid {
    const NAMES: [(&'static str, Self); 2] = [("ignore", Self::Ignore), ("method", Self::Method)];

    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, lid)| *lid)
            .ok_or(Error::Lid)
    }

    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, lid)| *lid == self)
            .map(|(name, _)| *name)
            .unwrap_or_default()
    }
}

/// Whether a boot on a laptop takes its laptop features unasked
/// (`--laptop auto|off`, [`crate::laptop`]): a hand-written opt-out setup
/// never writes, so the options revision stays 13.
pub const LAPTOP: &str = "--laptop";

/// `--laptop`'s value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Laptop {
    /// The default: on a laptop, behave as if `--battery`, `--lid method`,
    /// `--brightness-keys` and, with `--input` and a precision touchpad,
    /// `--trackpad mt2` were given, where the line does not give them.
    #[default]
    Auto,
    /// Take none of them: each is the opt-in its option is.
    Off,
}

impl Laptop {
    const NAMES: [(&'static str, Self); 2] = [("auto", Self::Auto), ("off", Self::Off)];

    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, laptop)| *laptop)
            .ok_or(Error::Laptop)
    }

    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, laptop)| *laptop == self)
            .map(|(name, _)| *name)
            .unwrap_or_default()
    }
}

/// Composes the frames of a laptop panel that an integrated GPU drives on
/// the discrete GPU that serves Metal (`--hybrid-scanout on|off`), as
/// Linux's PRIME render offload does on a laptop without a display mux:
/// the discrete GPU's Metal service imports the integrated GPU's three
/// scanout buffers, composes each frame into the hidden one and the
/// integrated GPU flips it on its vblank, where the CPU copied each frame's
/// rows. On amdgpu the buffers are made in system memory (GTT), which
/// another GPU can import. Off by default until proven on hardware: a
/// hand-written opt-in setup never writes, so the options revision stays
/// 13.
pub const HYBRID_SCANOUT: &str = "--hybrid-scanout";

/// The thermal policy an ASUS laptop's firmware is set to before macOS
/// starts (`--asus-mode performance|turbo|silent|off`), as Linux's
/// asus-wmi sets `throttle_thermal_policy`: a hand-written option setup
/// never writes, so the options revision stays 13. Without it an ASUS
/// laptop runs in performance (asus-wmi's default), whatever Windows last
/// chose; any other PC is left alone.
pub const ASUS_MODE: &str = "--asus-mode";

/// `--asus-mode`'s value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AsusMode {
    /// The default: the firmware's performance (balanced) policy, Linux's
    /// `ASUS_THROTTLE_THERMAL_POLICY_DEFAULT`.
    #[default]
    Performance,
    /// The firmware's turbo (overboost) policy: the loudest fans.
    Turbo,
    /// The firmware's silent policy.
    Silent,
    /// Leave the policy as the firmware has it.
    Off,
}

impl AsusMode {
    const NAMES: [(&'static str, Self); 4] = [
        ("performance", Self::Performance),
        ("turbo", Self::Turbo),
        ("silent", Self::Silent),
        ("off", Self::Off),
    ];

    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, mode)| *mode)
            .ok_or(Error::AsusMode)
    }

    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, mode)| *mode == self)
            .map(|(name, _)| *name)
            .unwrap_or_default()
    }
}

/// The power management of each GPU's PCI Express link
/// (`--gpu-aspm off|firmware`): `off` turns ASPM L0s and L1 and every L1 PM
/// Substate off at both ends of the link at the GPU's claim, as Linux's
/// `pcie_aspm.policy=performance` does, a test for GPUs that drop off the
/// bus while the firmware left L1 on. A hand-written opt-in setup never
/// writes, so the options revision stays 13; without it the link keeps
/// what the firmware set.
pub const GPU_ASPM: &str = "--gpu-aspm";

/// `--gpu-aspm`'s value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum GpuAspm {
    /// The default: the link's ASPM as the firmware left it, its L1 PM
    /// Substates set as Linux leaves them.
    #[default]
    Firmware,
    /// ASPM and the L1 PM Substates off at both ends.
    Off,
}

impl GpuAspm {
    const NAMES: [(&'static str, Self); 2] = [("firmware", Self::Firmware), ("off", Self::Off)];

    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, aspm)| *aspm)
            .ok_or(Error::GpuAspm)
    }

    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, aspm)| *aspm == self)
            .map(|(name, _)| *name)
            .unwrap_or_default()
    }
}

/// Runs the host's ACPI in hardware mode (`--acpi-hardware`): the SCI,
/// fixed events and GPEs, the embedded controller's queries and the
/// notifications they send ([`crate::acpi_hardware`]). A hand-written
/// opt-in setup never writes, so the options revision stays 13, and a
/// laptop does not take it unasked until it is proven on hardware.
pub const ACPI_HARDWARE: &str = "--acpi-hardware";

/// One host processor beyond the guest's PEs for the host's own work
/// (`--host-core on|off`, [`crate::host_core`]): the service turns and the
/// GPUs' pump leave PE 0's core. A hand-written opt-in, in a startup
/// choice of its own, that setup never writes, so the options revision
/// stays 13; off unless given. Any step that cannot be checked boots as
/// without it.
pub const HOST_CORE: &str = "--host-core";

/// Lets a guest whose kernel panicked run on (`--keep-running-on-panic`):
/// without it the run stops `guest_watch::PANIC_HOLD_MILLIS` after the
/// panic's first line when no reset follows (`crate::guest_watch`). A
/// hand-written opt-in for debugging that setup never writes, so the
/// options revision stays 13.
pub const KEEP_RUNNING_ON_PANIC: &str = "--keep-running-on-panic";
/// Keep the ITLB's lookup contexts across a TLBI of everything and verify
/// each entry against the tables before any lookup uses it again, instead
/// of forgetting them all (`--tlbi-keep on|off`, off unless given). A
/// hand-written opt-in setup never writes, so the options revision stays
/// 13; it stays off by default until a boot has proven it.
pub const TLBI_KEEP: &str = "--tlbi-keep";

/// With `--tlbi-keep on`, also walk every entry verification keeps in full
/// and drop it, counted as a mismatch, where the walk differs
/// (`--tlbi-verify-check`): a debug safety mode, hand-written like
/// `--acpi-hardware`, so the options revision stays 13.
pub const TLBI_VERIFY_CHECK: &str = "--tlbi-verify-check";

/// A read-only bring-up boot (`--core-trial`): runs a prepared `--bundle`
/// from the USB on an explicit `--native-cores` count, its disks backed by
/// engine memory (`--storage-ram`), so nothing it does persists. It is for
/// trying a many-core Mac's restore ramdisk, such as the M2 Ultra Mac
/// Studio's (Mac14,14) on 16 PEs, without installing it. Every option that
/// can reach a disk is refused ([`Constraint::CoreTrial`]), and the boot
/// opens no translation store and applies no pending disk plan. A
/// hand-written opt-in setup never writes, so the options revision stays 13.
pub const CORE_TRIAL: &str = "--core-trial";
/// Runs tier 2 (`--tier2 on|off`, off unless given): blocks the engine
/// finds hot are compiled again as superblocks (`stela_engine`'s
/// `machine::engine::tier2`), which no translation store keeps. A
/// hand-written opt-in setup never writes, so the options revision stays 13.
pub const TIER2: &str = "--tier2";

/// Checks tier 2 (`--tier2-check`, which runs tier 2): one entry in 64 into
/// a tier-2 block that only reads memory runs again as tier 1 from the same
/// start, and a block whose end differs goes for good, tier 1's end
/// standing. A debug mode, hand-written as [`TIER2`] is.
pub const TIER2_CHECK: &str = "--tier2-check";

/// Reads the rest of a translation pack read on demand into memory in the
/// background once the guest runs (`--pack-preload on|off`, off unless
/// given): large sequential reads of the USB on idle time, never ahead of a
/// lookup's own read, within the memory the pack's budget leaves
/// (`host_memory::bulk_bound`). `off` leaves the records to be read as
/// lookups ask for them, as before. A hand-written opt-in setup never
/// writes, so the options revision stays 13.
pub const PACK_PRELOAD: &str = "--pack-preload";

/// Allows the translation pack and pipeline store to open on an EFI system
/// partition (`--store-esp`, off by default). Like the boot log and FDR
/// volume, the store only reads and writes its preallocated file runs on the
/// FAT32 volume and is never handed to the guest, but writing hundreds of
/// MiB on an internal ESP shared with another OS requires explicit opt-in.
/// A hand-written opt-in setup never writes, so the options revision stays 13.
pub const STORE_ESP: &str = "--store-esp";

/// Cables an emulated Magic Trackpad 2 fed by the host's precision
/// touchpads (`--trackpad mt2|builtin`): a hand-written opt-in, in a
/// startup choice of its own, that setup never writes (so the options
/// revision stays 13). A laptop with a precision touchpad takes `mt2`
/// unasked ([`crate::laptop`]).
pub const TRACKPAD: &str = "--trackpad";

/// The trackpad `--trackpad` cables: a Magic Trackpad 2 (05AC:0265), or
/// the same device under the internal trackpad ID VoodooInput presents on
/// macOS 12 and later (05AC:0281).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestTrackpad {
    Mt2,
    Builtin,
}

impl GuestTrackpad {
    const NAMES: [(&'static str, Self); 2] = [("mt2", Self::Mt2), ("builtin", Self::Builtin)];

    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, kind)| *kind)
            .ok_or(Error::Trackpad)
    }

    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, kind)| *kind == self)
            .map(|(name, _)| *name)
            .unwrap_or_default()
    }
}

/// A `--audio-check` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AudioCheck {
    Playback,
    Duplex,
    TransportPlayback,
    TransportDuplex,
}

impl AudioCheck {
    const NAMES: [(&'static str, Self); 4] = [
        ("playback", Self::Playback),
        ("duplex", Self::Duplex),
        ("transport-playback", Self::TransportPlayback),
        ("transport-duplex", Self::TransportDuplex),
    ];

    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::NAMES
            .iter()
            .find(|(name, _)| *name == value)
            .map(|(_, mode)| *mode)
            .ok_or(Error::AudioMode)
    }

    pub fn name(self) -> &'static str {
        Self::NAMES
            .iter()
            .find(|(_, mode)| *mode == self)
            .map(|(name, _)| *name)
            .unwrap_or_default()
    }

    pub fn transport(self) -> bool {
        matches!(self, Self::TransportPlayback | Self::TransportDuplex)
    }

    pub fn duplex(self) -> bool {
        matches!(self, Self::Duplex | Self::TransportDuplex)
    }
}

/// Where a `--dump` range starts: a guest virtual address, or the stopped
/// PE's general register `xN` plus or minus an offset (`x21`, `x22+0x4000`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Address(u64),
    Register(usize, i64),
}

impl Base {
    /// Parse and check one option line.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let Some(register) = text.strip_prefix('x') else {
            return Ok(Self::Address(number(text)?));
        };
        let (index, offset) = match register.find(['+', '-']) {
            Some(at) => {
                let magnitude = number(&register[at + 1..])? as i64;
                let sign = if register.as_bytes()[at] == b'-' {
                    -1
                } else {
                    1
                };
                (&register[..at], sign * magnitude)
            }
            None => (register, 0),
        };
        match index.parse() {
            Ok(index) if index < 31 => Ok(Self::Register(index, offset)),
            _ => Err(Error::DumpRegister),
        }
    }

    pub fn resolve(self, x: &[u64; 31]) -> u64 {
        match self {
            Self::Address(address) => address,
            Self::Register(index, offset) => x[index].wrapping_add_signed(offset),
        }
    }
}

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Address(address) => write!(f, "{address:#x}"),
            Self::Register(index, 0) => write!(f, "x{index}"),
            Self::Register(index, offset) if offset < 0 => {
                write!(f, "x{index}-{:#x}", offset.unsigned_abs())
            }
            Self::Register(index, offset) => write!(f, "x{index}+{offset:#x}"),
        }
    }
}

/// A number in `stela.cfg`: decimal, or hexadecimal after `0x` with optional
/// `_` separators.
pub fn number(value: &str) -> Result<u64, Error> {
    match value.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(&hex.replace('_', ""), 16),
        None => value.parse(),
    }
    .map_err(|_| Error::Number)
}

/// The legacy HTTP-only host/path adapter. URLs that need a transport scheme
/// must use the original full URL; HTTPS cannot lose its security requirement.
pub fn split_url(url: &str) -> Result<(&str, &str)> {
    if !url.starts_with("http://") {
        return Err(refuse!("only http:// URLs are supported"));
    }
    let value = parse_url(url).map_err(Error::message)?;
    Ok((value.authority, value.target))
}

fn parse_url(url: &str) -> Result<stela_runtime::net::http::Url<'_>, Error> {
    // Preserve scheme/path diagnostic priority, then require the one shared
    // syntax and transport-policy parser for every accepted value.
    if !["http://", "https://"].iter().any(|prefix| {
        url.get(..prefix.len())
            .is_some_and(|part| part.eq_ignore_ascii_case(prefix))
    }) {
        return Err(Error::UrlScheme);
    }
    stela_runtime::net::http::Url::parse(url).map_err(|error| match error {
        stela_runtime::net::http::UrlError::Scheme => Error::UrlScheme,
        stela_runtime::net::http::UrlError::Path => Error::UrlPath,
        stela_runtime::net::http::UrlError::Host if url.ends_with("://") => Error::UrlPath,
        stela_runtime::net::http::UrlError::Host => Error::UrlHost,
        other => Error::Url(other),
    })
}

/// The system-mode options of one `stela.cfg` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct System {
    pub dram_base: u64,
    /// `--dram-base` was given; otherwise a bundle's own base applies.
    pub dram_explicit: bool,
    pub load: u64,
    pub entry: u64,
    pub x0: u64,
    pub budget: u64,
    /// Load the boot bundle the loader read instead of `source.bin`.
    pub bundle: bool,
    /// The bundle's directory on the Stela volume (`--bundle DIR`).
    pub bundle_directory: Option<String>,
    /// Build the boot bundle from the installed system on this APFS
    /// partition instead (`SERIAL:GUID`).
    pub preboot: Option<Target>,
    /// Allow SIP-protected filesystem writes for this explicit maintenance boot.
    pub maintenance_write: bool,
    /// Boot the installed system single-user, for maintenance at its console.
    pub single_user: bool,
    /// This boot is the automatic Metal plugin repair NVRAM asked for
    /// (`--bundle-repair`, never from `stela.cfg`): single-user with
    /// filesystem protection off, its console driven by the engine
    /// (`bundle_repair`).
    pub bundle_repair: bool,
    /// Keep the newest presented frame in host memory for a debugger to read:
    /// a passed-through GPU's picture otherwise leaves only through its port.
    pub scanout_mirror: bool,
    /// The NVRAM boot volume the loader chose (`--boot-volume`), naming the
    /// Preboot disk's container and volume group.
    pub boot_volume: Option<BootVolume>,
    /// NVRAM asked for a safe-mode boot (`--safe-boot`).
    pub safe_boot: bool,
    /// The entry origin kept after NVRAM's one-shot command is consumed.
    pub boot_command: Option<BootCommand>,
    /// NVRAM chose a staged macOS update (`--upgrade`): build from the
    /// Preboot disk's Update volume.
    pub upgrade: bool,
    /// NVRAM chose a recoveryOS the Preboot disk holds: its Recovery
    /// volume's paired copy (`--paired-recovery`) or its RecoveryOSContainer's
    /// System Recovery (`--system-recovery`).
    pub recovery: Option<recovery::Kind>,
    /// One host partition backing all ANS namespaces.
    pub storage: Option<Target>,
    /// Instead, this many bytes of engine memory back them, and nothing
    /// persists (`--storage-ram`).
    pub storage_ram: Option<u64>,
    /// The host partition holding the NOR flash image (`--nor`); the
    /// `--storage` partition itself keeps it in its tail.
    pub nor: Option<Target>,
    /// `--restore-study`.
    pub restore: bool,
    pub restore_source: Option<Target>,
    /// `--restore-manifest PATH` was given.
    pub restore_manifest: bool,
    pub restore_manifest_path: Option<String>,
    pub restore_identity: Option<usize>,
    /// The install medium's `payload.json` (`--install`), whose directory
    /// holds its pieces: a restore with Apple's stock options.
    pub install: Option<String>,
    /// The install medium's partition, by its unique GUID alone.
    pub install_source: Option<Guid>,
    /// The install medium's read-ahead in 1 MiB chunks
    /// ([`MEDIUM_READ_AHEAD`]); `None` takes the engine's default.
    pub medium_read_ahead: Option<usize>,
    /// Refuse a payload without recorded block hashes, which would be read
    /// whole before StartRestore (`--verify-on-read`).
    pub verify_on_read: bool,
    /// Restore with the inventory's Update identity (`--update-restore`).
    pub update_restore: bool,
    /// Use restored's development-board policy to keep and report FDR
    /// failures while allowing the erase restore to continue
    /// (`--development-restore`), a degraded mode.
    pub development_restore: bool,
    /// The disk's system was installed by a development restore, so it boots
    /// as the same development board; set from its bundle, not a flag.
    pub development_board: bool,
    /// Answer device accesses no model implements and list them
    /// (`--survey`): research runs only.
    pub survey: bool,
    /// Leap the counter over waits of every PE (`--idle-skip`): boot and
    /// install runs, not interactive use.
    pub idle_skip: bool,
    /// Cable the native USB keyboard and pointer to the last USB-C
    /// controller and feed it the host's virtio-input devices (`--input`).
    pub input: bool,
    /// Cable an emulated Magic Trackpad 2 beside the native keyboard and
    /// pointer, fed whole frames by the host's precision touchpads, which
    /// then no longer move the native mouse ([`TRACKPAD`], with `--input`).
    pub trackpad: Option<GuestTrackpad>,
    /// Log every packet of the guest's Bluetooth controller, 1024 per
    /// configuration (`--bluetooth-trace`), masked: addresses keep their
    /// vendor half and last byte, names, payloads and keys are hidden. A raw
    /// capture is not offered.
    pub bluetooth_trace: bool,
    /// Lend the host's Bluetooth controller to the guest behind the model of
    /// Apple's module, which answers its vendor commands and takes over
    /// when the host's fails or stalls (`--bluetooth-lend`). Without it the
    /// guest gets the model alone.
    pub bluetooth_lend: bool,
    /// Explicit native executors and guest PEs (`--native-cores N`), one per
    /// logical processor; SMT siblings count after every physical core.
    pub native_cores: Option<usize>,
    /// The source PE count (`--guest-pes N`) recorded by setup for disk
    /// boots whose verified DeviceTree is loaded after firmware exit.
    pub guest_pes: Option<usize>,
    /// The board's code window in MiB ([`CODE_WINDOW`]): whole
    /// [`crate::native_resources::CODE_ALIGNMENT`] steps within the
    /// window's bounds. Each MiB past the sized window takes two from the
    /// guest (the window and its block records); the guest keeps its floor.
    pub code_window: Option<u64>,
    /// Isolate no branch predictions between guest contexts ([`NO_IBPB`]):
    /// no IBPB and return stack refill at each change of the guest's
    /// translation regime, table bases or VMID, and no FEAT_CSV2 disclosed
    /// to the guest. This gives up Spectre-v2 (branch target injection)
    /// isolation between the guest's address spaces, its processes, and its
    /// translation regimes, for the time each barrier and the predictions
    /// it discards cost; a measurement option, off unless asked for.
    pub no_ibpb: bool,
    /// The latest a busy PE's timer interrupt comes after its previous one,
    /// in microseconds ([`TIMER_DELAY`]), in place of the engine's 10 ms: a
    /// PE that has not waited since its last timer interrupt takes the next
    /// once it had the time to retire the timer path's share of work at its
    /// rate, or after this delay if that is sooner. A shorter delay brings a
    /// slow PE's timers closer to their deadlines and spends more of its
    /// time in timer interrupts.
    pub timer_delay: Option<u64>,
    /// The size a GPU's display is taken in ([`DISPLAY_SIZE`]).
    pub display_size: Option<(u32, u32)>,
    /// Check owned AP startup/host resources, then stop before guest entry.
    pub native_bootstrap_check: bool,
    /// Bounded checked-memory kernel execution on the selected cores.
    pub native_shared_check: bool,
    /// Emit full artifact identities (`--native-artifacts`).
    pub native_artifacts: bool,
    /// Execute PEs in checked native rounds on their assigned workers
    /// (`--native-rounds`) instead of serialized chained blocks on the BSP.
    pub native_rounds: bool,
    /// Run each PE on its own host core, the default. `--serialized` runs
    /// every PE on the BSP instead, as native rounds and checks do.
    pub parallel: bool,
    /// Time the engine's phases and report them with each heartbeat
    /// (`--profile`).
    pub profile: bool,
    /// What the host does with its lid (`--lid`); [`Lid::Ignore`] unless
    /// given ([`Self::lid`]).
    pub lid: Option<Lid>,
    /// Ask macOS to sleep when the lid darkens the panel, with a HID System
    /// Sleep on the guest keyboard's System Control interface, and wake it
    /// with its power button when the panel lights again (`--lid-sleep`,
    /// with `--lid method`).
    pub lid_sleep: bool,
    /// Step a display output with `_BCL` and `_BCM` in the firmware's
    /// `_DOD` at its brightness notifications (`--brightness-keys`): Linux
    /// does only where ACPI video owns the backlight, which Stela cannot
    /// tell. A laptop takes it unasked, as it takes `--battery` and
    /// `--lid method` ([`crate::laptop`]).
    pub brightness_keys: bool,
    /// Run the host's ACPI in hardware mode ([`ACPI_HARDWARE`]).
    pub acpi_hardware: bool,
    /// [`HOST_CORE`]'s value, unset where the line has none
    /// ([`Self::host_core`]).
    pub host_core: Option<bool>,
    /// Run on after a guest kernel panic ([`KEEP_RUNNING_ON_PANIC`]).
    pub keep_running_on_panic: bool,
    /// [`TLBI_KEEP`]'s value, unset where the line has none
    /// ([`Self::tlbi_keep`]).
    pub tlbi_keep: Option<bool>,
    /// Walk every entry a kept context's verification keeps in full as
    /// well ([`TLBI_VERIFY_CHECK`]).
    pub tlbi_verify_check: bool,
    /// A read-only bring-up boot ([`CORE_TRIAL`]).
    pub core_trial: bool,
    /// Run tier 2 ([`TIER2`]): `Some(true)` for `on`, `Some(false)` for
    /// `off`, `None` unless given (off).
    pub tier2: Option<bool>,
    /// Check tier 2 ([`TIER2_CHECK`]), which runs it.
    pub tier2_check: bool,
    /// Preload the translation pack in the background ([`PACK_PRELOAD`]):
    /// `None` unless given, which does not preload ([`Self::pack_preload`]).
    pub pack_preload: Option<bool>,
    /// Allow the translation and pipeline store on an EFI system partition
    /// ([`STORE_ESP`]); off by default.
    pub store_esp: bool,
    /// Whether a laptop takes its laptop features unasked ([`LAPTOP`]);
    /// [`Laptop::Auto`] unless given ([`Self::laptop`]).
    pub laptop: Option<Laptop>,
    /// Whether the discrete GPU composes an integrated GPU's panel
    /// ([`HYBRID_SCANOUT`]); off unless given ([`Self::hybrid_scanout`]).
    pub hybrid_scanout: Option<bool>,
    /// The ASUS thermal policy set before macOS starts ([`ASUS_MODE`]);
    /// [`AsusMode::Performance`] unless given ([`Self::asus_mode`]).
    pub asus_mode: Option<AsusMode>,
    /// The GPU links' power management ([`GPU_ASPM`]);
    /// [`GpuAspm::Firmware`] unless given ([`Self::gpu_aspm`]).
    pub gpu_aspm: Option<GpuAspm>,
    /// [`AMX_NATIVE`]'s value, unset where the line has none
    /// ([`Self::amx_model`]).
    pub amx_native: Option<AmxModel>,
    /// Replace the guest functions HLE has signatures for with native
    /// routines (`--hle`); off by default.
    pub hle: bool,
    /// The routines `--hle` leaves translated (`--hle-off ID[,ID...]`).
    pub hle_off: Vec<stela_engine::hle::Id>,
    /// The machine's ECID for a bundle built from the Preboot volume
    /// (`--ecid HEX`, nonzero).
    pub ecid: Option<u64>,
    /// POST once to this `http://` URL at start and report the reply
    /// (`--network-check URL`).
    pub network_check: Option<String>,
    /// Check exclusively owned conventional HDA after ExitBootServices.
    pub audio_check: Option<AudioCheck>,
    /// Explicit whole-controller handoff for the audio check's physical clock.
    pub audio_own_hpet: bool,
    /// Exclusive handoff of the original IOAPICs through shutdown.
    pub native_pci_own_ioapic: bool,
    /// Whole host disks, by serial, that the guest sees as USB mass
    /// storage behind the native hub (`--usb-storage SERIAL`, repeatable).
    pub usb_storage: Vec<String>,
    /// USB4 devices that get a PCIe tunnel where no IOMMU confines their DMA
    /// (`--usb4-approve UUID`, repeatable).
    pub usb4_approved: Vec<Uuid>,
    /// Every other host disk the engine does not open itself is USB mass
    /// storage too, up to the hub's free ports (`--external-disks`).
    pub external_disks: bool,
    /// Give the guest a USB Ethernet adapter bridged to a host network
    /// adapter of its own (`--guest-network`).
    pub guest_network: bool,
    /// Give the guest's SMC a battery and AC adapter: the host's
    /// (`--battery`) or a synthetic one (`--test-battery PERCENT,STATE`).
    /// Without either the SMC answers as the Mac mini's.
    pub battery: Option<Battery>,
    /// Join this Wi-Fi network for the mount's network (`--wifi SSID`). The
    /// line writes `%`, whitespace and control characters as `%XX`.
    pub ssid: Option<String>,
    /// The ESP file holding the network's passphrase or PSK (`--wifi-key
    /// PATH`); `DEFAULT_WIFI_KEY` when `--wifi` is set without it.
    pub wifi_key: Option<String>,
    /// The saved network (`WIFI_SAVED`) to join first this boot, before the
    /// `--wifi` one (`--wifi-prefer SSID`, written as `--wifi` is): the
    /// startup menu's choice. A name no network carries changes nothing.
    pub wifi_prefer: Option<String>,
    /// The ISO 3166-1 alpha-2 regulatory country, uppercase
    /// (`--wifi-country XX`).
    pub wifi_country: Option<String>,
    /// The mount network's IPv4 address, set by hand instead of by DHCP
    /// (`--ipv4 ADDRESS/PREFIX`).
    pub ipv4: Option<StaticIpv4>,
    /// Its default router (`--ipv4-gateway ADDRESS`).
    pub ipv4_gateway: Option<core::net::Ipv4Addr>,
    /// The DNS servers, in place of DHCP's and router advertisements'
    /// (`--dns SERVER[,SERVER...]`).
    pub dns: Vec<core::net::IpAddr>,
    /// Advertise and log the SEP services whose contracts are not recovered
    /// (`--sep-observe`), each request refused by name.
    pub sep_observe: bool,
    /// Stop when a PE reaches one of these guest PCs (`--break`).
    pub breakpoints: Vec<u64>,
    /// Log, without stopping, when a PE reaches one of these guest PCs
    /// (`--trace`).
    pub traces: Vec<u64>,
    /// Log raw guarded entries, exits, exceptions and returns (`--monitor-trace`).
    pub monitor_trace: bool,
    /// Log every display swap's DCP calls, present and callback (`--display-trace`).
    pub display_trace: bool,
    /// Log every device access in these physical ranges (`--watch BASE,BYTES`).
    pub watches: Vec<(u64, u64)>,
    /// Guest virtual ranges the stop's report shows (`--dump BASE,BYTES`).
    pub dumps: Vec<(Base, u64)>,
}

impl Default for System {
    fn default() -> Self {
        Self {
            dram_base: DRAM_BASE,
            dram_explicit: false,
            load: DRAM_BASE,
            entry: DRAM_BASE,
            x0: 0,
            budget: 0,
            bundle: false,
            bundle_directory: None,
            preboot: None,
            boot_volume: None,
            safe_boot: false,
            maintenance_write: false,
            single_user: false,
            bundle_repair: false,
            scanout_mirror: false,
            boot_command: None,
            upgrade: false,
            recovery: None,
            storage: None,
            storage_ram: None,
            nor: None,
            restore: false,
            restore_source: None,
            restore_manifest: false,
            restore_manifest_path: None,
            restore_identity: None,
            install: None,
            install_source: None,
            medium_read_ahead: None,
            verify_on_read: false,
            update_restore: false,
            development_restore: false,
            development_board: false,
            survey: false,
            idle_skip: false,
            input: false,
            trackpad: None,
            bluetooth_trace: false,
            bluetooth_lend: false,
            native_cores: None,
            guest_pes: None,
            code_window: None,
            no_ibpb: false,
            timer_delay: None,
            display_size: None,
            native_bootstrap_check: false,
            native_shared_check: false,
            native_artifacts: false,
            native_rounds: false,
            parallel: true,
            profile: false,
            lid: None,
            lid_sleep: false,
            brightness_keys: false,
            acpi_hardware: false,
            host_core: None,
            keep_running_on_panic: false,
            tlbi_keep: None,
            tlbi_verify_check: false,
            core_trial: false,
            tier2: None,
            tier2_check: false,
            pack_preload: None,
            store_esp: false,
            laptop: None,
            hybrid_scanout: None,
            asus_mode: None,
            gpu_aspm: None,
            amx_native: None,
            hle: false,
            hle_off: Vec::new(),
            ecid: None,
            network_check: None,
            audio_check: None,
            audio_own_hpet: false,
            native_pci_own_ioapic: false,
            usb_storage: Vec::new(),
            usb4_approved: Vec::new(),
            external_disks: false,
            guest_network: false,
            battery: None,
            ssid: None,
            wifi_key: None,
            wifi_prefer: None,
            wifi_country: None,
            ipv4: None,
            ipv4_gateway: None,
            dns: Vec::new(),
            sep_observe: false,
            breakpoints: Vec::new(),
            traces: Vec::new(),
            monitor_trace: false,
            display_trace: false,
            watches: Vec::new(),
            dumps: Vec::new(),
        }
    }
}

/// A host address and its subnet's prefix length (`--ipv4`), written
/// `ADDRESS/PREFIX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticIpv4 {
    pub address: core::net::Ipv4Addr,
    pub prefix: u8,
}

impl StaticIpv4 {
    /// `ADDRESS/PREFIX` naming a unicast host of its subnet: a prefix of 1
    /// to 32, and below /31 neither the subnet's network nor its broadcast
    /// address.
    pub fn parse(word: &str) -> Option<Self> {
        let (address, prefix) = word.split_once('/')?;
        let address: core::net::Ipv4Addr = address.parse().ok()?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|prefix| (1..=32).contains(prefix))?;
        let ipv4 = Self { address, prefix };
        let host = u32::from(address) & !ipv4.mask();
        let usable = !address.is_unspecified()
            && !address.is_multicast()
            && !address.is_broadcast()
            && (prefix >= 31 || (host != 0 && host != !ipv4.mask()));
        usable.then_some(ipv4)
    }
    fn mask(self) -> u32 {
        u32::MAX
            .checked_shl(32 - u32::from(self.prefix))
            .unwrap_or(0)
    }
    /// Whether `other` is another host of this subnet.
    pub fn neighbors(self, other: core::net::Ipv4Addr) -> bool {
        other != self.address
            && u32::from(other) & self.mask() == u32::from(self.address) & self.mask()
    }
}

impl fmt::Display for StaticIpv4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

/// A `--dns` word: 1 to [`MAX_DNS_SERVERS`] distinct addresses, IPv4 or
/// IPv6, separated by commas.
pub fn dns_servers(word: &str) -> Option<Vec<core::net::IpAddr>> {
    let mut servers = Vec::new();
    for server in word.split(',') {
        let server: core::net::IpAddr = server.parse().ok()?;
        if server.is_unspecified() || server.is_multicast() || servers.contains(&server) {
            return None;
        }
        servers.push(server);
    }
    (servers.len() <= MAX_DNS_SERVERS).then_some(servers)
}

struct Servers<'a>(&'a [core::net::IpAddr]);

impl fmt::Display for Servers<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, server) in self.0.iter().enumerate() {
            if index != 0 {
                f.write_str(",")?;
            }
            write!(f, "{server}")?;
        }
        Ok(())
    }
}

/// A `--wifi` word: `%XX` escapes decoded, 1 to 32 bytes of UTF-8.
fn ssid(word: &str) -> Result<String, Error> {
    const MALFORMED: Error = Error::WifiNetwork;
    let mut bytes = Vec::with_capacity(word.len());
    let mut rest = word.as_bytes();
    while let Some((&byte, tail)) = rest.split_first() {
        rest = tail;
        if byte != b'%' {
            bytes.push(byte);
            continue;
        }
        let digits = rest.get(..2).ok_or(MALFORMED)?;
        let digits = core::str::from_utf8(digits).map_err(|_| MALFORMED)?;
        bytes.push(u8::from_str_radix(digits, 16).map_err(|_| MALFORMED)?);
        rest = &rest[2..];
    }
    if !SSID_BYTES.contains(&bytes.len()) {
        return Err(MALFORMED);
    }
    String::from_utf8(bytes).map_err(|_| MALFORMED)
}

/// `name` as one `--wifi` word, as the startup menu writes `--wifi-prefer`.
pub fn wifi_word(name: &str) -> String {
    alloc::format!("{}", Ssid(name))
}

/// An SSID as one `--wifi` word: `%`, whitespace and control characters as
/// `%XX`.
struct Ssid<'a>(&'a str);

impl fmt::Display for Ssid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            if character == '%' || character.is_whitespace() || character.is_control() {
                let mut bytes = [0; 4];
                for byte in character.encode_utf8(&mut bytes).bytes() {
                    write!(f, "%{byte:02X}")?;
                }
            } else {
                write!(f, "{character}")?;
            }
        }
        Ok(())
    }
}

/// A `--hle-off` word: distinct routine names separated by commas.
fn hle_routines(word: &str) -> Result<Vec<stela_engine::hle::Id>, Error> {
    let mut routines = Vec::new();
    for name in word.split(',') {
        let routine = stela_engine::hle::Id::from_name(name).ok_or(Error::HleId)?;
        if routines.contains(&routine) {
            return Err(Error::HleId);
        }
        routines.push(routine);
    }
    Ok(routines)
}

/// Routines as one `--hle-off` word.
struct Routines<'a>(&'a [stela_engine::hle::Id]);

impl fmt::Display for Routines<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, routine) in self.0.iter().enumerate() {
            if index != 0 {
                f.write_str(",")?;
            }
            f.write_str(routine.name())?;
        }
        Ok(())
    }
}

fn flag(set: &mut bool, duplicate: Error) -> Result<(), Error> {
    if core::mem::replace(set, true) {
        return Err(duplicate);
    }
    Ok(())
}

impl System {
    /// What the host does with its lid: `--lid`, else nothing.
    pub fn lid(&self) -> Lid {
        self.lid.unwrap_or_default()
    }

    /// Whether a laptop takes its laptop features unasked: `--laptop`,
    /// else [`Laptop::Auto`].
    pub fn laptop(&self) -> Laptop {
        self.laptop.unwrap_or_default()
    }

    /// Whether the discrete GPU composes an integrated GPU's panel:
    /// `--hybrid-scanout`, else off.
    pub fn hybrid_scanout(&self) -> bool {
        self.hybrid_scanout.unwrap_or(false)
    }

    /// The ASUS thermal policy set before macOS starts: `--asus-mode`,
    /// else [`AsusMode::Performance`].
    pub fn asus_mode(&self) -> AsusMode {
        self.asus_mode.unwrap_or_default()
    }

    /// Whether the ITLB keeps its contexts across a TLBI of everything and
    /// verifies them ([`TLBI_KEEP`]), and whether every entry it keeps is
    /// walked in full as well ([`TLBI_VERIFY_CHECK`], only with the first):
    /// off unless `--tlbi-keep on`.
    pub fn tlbi_keep(&self) -> (bool, bool) {
        let keep = self.tlbi_keep.unwrap_or(false);
        (keep, keep && self.tlbi_verify_check)
    }

    /// The GPU links' power management: `--gpu-aspm`, else
    /// [`GpuAspm::Firmware`].
    pub fn gpu_aspm(&self) -> GpuAspm {
        self.gpu_aspm.unwrap_or_default()
    }

    /// Whether the translation pack is preloaded in the background: only
    /// with `--pack-preload on`. Off by default: on Garvit's 16 GB laptop the
    /// preload's memory shrank the code window (1280 to 1200 MiB) and raised
    /// re-installs (7-32% to 43-49% again), costing more than its lookups
    /// saved, since compile was 1-4% of PE time (boots 29-30, 2026-11-23).
    pub fn pack_preload(&self) -> bool {
        self.pack_preload == Some(true)
    }

    /// Whether tier 2 runs: `--tier2 on`, or `--tier2-check`.
    pub fn tier2_runs(&self) -> bool {
        self.tier2 == Some(true) || self.tier2_check
    }

    /// The trackpad this boot cables: `--trackpad`, on the hub `--input`
    /// cables, so none without host input. The hub's disk-port count and
    /// the cabling both read this, so they agree.
    pub fn guest_trackpad(&self) -> Option<GuestTrackpad> {
        self.trackpad.filter(|_| self.input)
    }

    /// This boot starts the macOS the Preboot disk holds, which needs a GPU;
    /// its recoveryOS and a staged update's installer show on the firmware's
    /// display, as a restore does.
    pub fn boots_macos(&self) -> bool {
        self.preboot.is_some() && self.recovery.is_none() && !self.upgrade
    }

    /// This boot starts a full system from the boot disk, the installed
    /// macOS or a recoveryOS, whose WindowServer, and in the installed macOS
    /// its other Metal clients, use a Metal device whenever one exists. A
    /// restore and a staged update run Apple's restore ramdisk
    /// (`-restore`), which starts no WindowServer and no Metal client.
    pub fn starts_metal_clients(&self) -> bool {
        self.preboot.is_some() && !self.upgrade
    }

    /// The AMX register operations the reference model completes alone:
    /// none unless `--amx-native` names some or `off`.
    pub fn amx_model(&self) -> AmxModel {
        self.amx_native.unwrap_or(AmxModel::NONE)
    }

    /// Whether this boot hides the guest's AGX model (`sgx` and its `gfx-asc`
    /// coprocessor) from macOS, `metal_device` saying whether a host GPU
    /// serves macOS's Metal through StelaGPU.
    ///
    /// The model runs no GPU work: a Metal client's command buffers on it
    /// never complete, so Apple's GPU kext stops its firmware for recovery,
    /// and macOS panics when the model cannot follow that stop (a kext
    /// revision whose initdata layout it has not checked). So no boot that
    /// starts Metal clients sees it ([`Self::starts_metal_clients`]): with a
    /// host GPU StelaGPU is the only Metal device, and without one the boot
    /// has none. The model draws nothing, so hiding it takes nothing from a
    /// boot without a GPU: a single-user or repair boot's console needs no
    /// Metal device, and a recoveryOS's WindowServer composites in software
    /// when it finds none (SkyLight of the 26B123 arm64e cache carries a
    /// software compositor: "The software renderer does not support 10-bit
    /// or YUV DisplayStream output", "We do not support zoom and software
    /// compositor (yet)"), where with the model it would choose the model.
    /// A restore and a staged update keep the model as they always have: they
    /// open no host GPU, run no Metal client (no install log shows a work
    /// doorbell or a protected context in 1-2 h), and the model's firmware
    /// start is all they have of a GPU.
    pub fn hides_agx(&self, metal_device: bool) -> bool {
        metal_device || self.starts_metal_clients()
    }

    /// The boot this is, by the name its `POWER` line gives, when the
    /// guest's SMC takes no battery whatever `--battery` or `--test-battery`
    /// asks, and answers as the Mac mini's; `restoring` when the engine
    /// runs a restore. An install, a restore study and a staged update run
    /// Apple's restore ramdisk (`-restore`), and a recoveryOS and the Metal
    /// plugin repair mend the installed system: none needs a battery, and a
    /// battery macOS read as empty or critical, which it shuts down at, or
    /// whose `lpem` powers the laptop off, would cut that work short. The
    /// installed macOS takes one, in single-user and safe mode too.
    pub fn battery_withheld(&self, restoring: bool) -> Option<&'static str> {
        if restoring || self.install.is_some() || self.restore {
            Some("the macOS installer")
        } else if self.upgrade {
            Some("a staged macOS update")
        } else if self.recovery.is_some() {
            Some("recoveryOS")
        } else if self.bundle_repair {
            Some("the Metal plugin repair")
        } else {
            None
        }
    }

    /// Whether the line asks for a host core ([`HOST_CORE`] `on`); off
    /// unless given.
    pub fn host_core(&self) -> bool {
        self.host_core == Some(true)
    }

    /// Select the exact number of host processors the loader reserves.
    /// A disk-derived count is rechecked against the live source before SIPI.
    pub fn assigned_native_cores(
        &self,
        available: usize,
        verified_bundle_pes: Option<usize>,
    ) -> crate::Result<usize> {
        use crate::topology::{assignment_count, guest_assignment_count};
        use stela_contracts::refuse;
        if self.native_bootstrap_check || self.native_shared_check {
            let count = self.native_cores.ok_or(refuse!(
                "native bootstrap check needs an explicit processor count"
            ))?;
            return assignment_count(Some(count), available);
        }
        if !self.parallel && !self.native_rounds {
            if self.native_cores.is_some_and(|count| count != 1) {
                return Err(refuse!(
                    "serialized guest execution claims exactly one native core"
                ));
            }
            return assignment_count(Some(1), available);
        }
        let source_pes = if let Some(verified) = verified_bundle_pes {
            verified
        } else if self.preboot.is_some() {
            self.native_cores.or(self.guest_pes).ok_or(refuse!(
                "Preboot CPU count is unavailable before reservation; run stambha repair or specify --guest-pes N"
            ))?
        } else {
            1
        };
        guest_assignment_count(self.native_cores, available, source_pes)
    }

    /// Join the reservation to the verified live topology before starting APs.
    pub fn validate_native_cores(
        &self,
        available: usize,
        reserved: usize,
        source_pes: usize,
    ) -> crate::Result<()> {
        use stela_contracts::refuse;
        if self.preboot.is_some()
            && (self.parallel || self.native_rounds)
            && self.native_cores.is_none()
            && self.guest_pes != Some(source_pes)
        {
            return Err(refuse!(
                "Preboot CPU count changed; run stambha repair or update --guest-pes N"
            ));
        }
        // Fewer cores than assigned run when firmware leaves no AP startup
        // page or an AP fails to start.
        if reserved == 0 || reserved > self.assigned_native_cores(available, Some(source_pes))? {
            return Err(refuse!(
                "verified live source and reserved native core count disagree; check --guest-pes and --native-cores"
            ));
        }
        Ok(())
    }

    /// The line starts with `--system`.
    pub fn is_system(text: &str) -> bool {
        text.split_ascii_whitespace().next() == Some(SYSTEM)
    }

    /// Parse a line the mount runs: `parse`, refusing an unreplaced `@disk`.
    pub fn parse_resolved(text: &str) -> Result<Self, Error> {
        let options = Self::parse(text)?;
        if [&options.storage, &options.nor, &options.preboot]
            .into_iter()
            .flatten()
            .any(is_chosen)
        {
            return Err(Error::Constraint(Constraint::UnresolvedDisk));
        }
        Ok(options)
    }

    /// The first authored fixture requested by these typed options. Shared
    /// parsing remains stable across mounts; production mounts reject a fixture
    /// before taking over hardware.
    pub fn diagnostic_option(&self) -> Option<&'static str> {
        [
            (self.native_bootstrap_check, "--native-bootstrap-check"),
            (self.native_shared_check, "--native-shared-check"),
            (self.audio_check.is_some(), "--audio-check"),
            (self.audio_own_hpet, "--audio-own-hpet"),
            (self.network_check.is_some(), "--network-check"),
        ]
        .into_iter()
        .find_map(|(enabled, flag)| enabled.then_some(flag))
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        parse::system(text)
    }

    /// Check complete-record constraints in their established diagnostic order.
    /// This does not apply parsing defaults or mutate the record.
    pub fn check(&self) -> Result<(), Error> {
        validate::system(self)
    }
}

struct Line<'a, 'b>(&'a mut fmt::Formatter<'b>);

impl Line<'_, '_> {
    fn flag(&mut self, name: &str, set: bool) -> fmt::Result {
        if set {
            write!(self.0, " {name}")?;
        }
        Ok(())
    }
    fn value(&mut self, name: &str, value: Option<impl fmt::Display>) -> fmt::Result {
        if let Some(value) = value {
            write!(self.0, " {name} {value}")?;
        }
        Ok(())
    }
}

struct Partition<'a>(&'a Target);

fn written(target: &Option<Target>) -> Option<Partition<'_>> {
    target.as_ref().map(Partition)
}

impl fmt::Display for Partition<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if is_chosen(self.0) {
            return f.write_str(mount_interface::CHOSEN_DISK);
        }
        write!(f, "{}:{}", self.0.serial, self.0.partition)
    }
}

/// The partition `stela.efi`'s Install macOS chooses, written `@disk`
/// (`mount_interface::CHOSEN_DISK`). The mount replaces each `@disk` with the
/// chosen `SERIAL:GUID` before the engine reads the line
/// (`mount_interface::with_disk`).
pub fn chosen_disk() -> Target {
    Target {
        serial: String::from(mount_interface::CHOSEN_DISK),
        partition: Guid([0; 16]),
    }
}

/// `target` is `chosen_disk`.
pub fn is_chosen(target: &Target) -> bool {
    target.serial == mount_interface::CHOSEN_DISK && target.partition.is_zero()
}

fn partition(value: &str, argument: TargetArgument) -> Result<Target, Error> {
    if value == mount_interface::CHOSEN_DISK {
        return Ok(chosen_disk());
    }
    value
        .parse()
        .map_err(|source| Error::Target { argument, source })
}

struct Hex(u64);

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

/// An ECID as 16 hexadecimal digits, as `stela` prints it.
struct Ecid(u64);

impl fmt::Display for Ecid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// The canonical option line: `--system`, then each option that differs
/// from its default, in a fixed order. `System::parse` reads it back to an
/// equal record.
impl fmt::Display for System {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(SYSTEM)?;
        let mut line = Line(f);
        line.value("--storage", written(&self.storage))?;
        line.value("--storage-ram", self.storage_ram.map(Hex))?;
        line.value("--nor", written(&self.nor))?;
        if self.preboot.is_some() {
            line.value("--preboot", written(&self.preboot))?;
        }
        line.value("--bundle", self.bundle_directory.as_deref())?;
        line.value("--ecid", self.ecid.map(Ecid))?;
        line.value(
            boot_selection::BOOT_VOLUME_OPTION,
            self.boot_volume
                .as_ref()
                .map(|volume| String::from_utf8_lossy(&volume.encode()).into_owned()),
        )?;
        line.value(
            boot_selection::BOOT_COMMAND_OPTION,
            self.boot_command.map(|command| command as u8),
        )?;
        line.flag(boot_selection::SAFE_BOOT_OPTION, self.safe_boot)?;
        line.flag(MAINTENANCE_WRITE, self.maintenance_write)?;
        line.flag(SINGLE_USER, self.single_user)?;
        line.flag(boot_selection::BUNDLE_REPAIR_OPTION, self.bundle_repair)?;
        line.flag(SCANOUT_MIRROR, self.scanout_mirror)?;
        line.flag(boot_selection::UPGRADE_OPTION, self.upgrade)?;
        line.flag(
            boot_selection::PAIRED_RECOVERY_OPTION,
            self.recovery == Some(recovery::Kind::Paired),
        )?;
        line.flag(
            boot_selection::SYSTEM_RECOVERY_OPTION,
            self.recovery == Some(recovery::Kind::System),
        )?;
        line.flag("--restore-study", self.restore)?;
        line.value("--restore-source", written(&self.restore_source))?;
        line.value("--restore-manifest", self.restore_manifest_path.as_deref())?;
        line.value("--restore-identity", self.restore_identity)?;
        line.value(INSTALL, self.install.as_deref())?;
        line.value(INSTALL_SOURCE, self.install_source)?;
        line.value(MEDIUM_READ_AHEAD, self.medium_read_ahead)?;
        line.flag(VERIFY_ON_READ, self.verify_on_read)?;
        line.flag(UPDATE_RESTORE, self.update_restore)?;
        line.flag("--development-restore", self.development_restore)?;
        for serial in &self.usb_storage {
            line.value("--usb-storage", Some(serial))?;
        }
        for uuid in &self.usb4_approved {
            line.value(USB4_APPROVE, Some(uuid))?;
        }
        line.flag(EXTERNAL_DISKS, self.external_disks)?;
        line.flag("--guest-network", self.guest_network)?;
        line.flag(BATTERY, self.battery == Some(Battery::Host))?;
        line.value(
            TEST_BATTERY,
            match self.battery {
                Some(Battery::Test { percent, state }) => Some(TestBattery(percent, state)),
                _ => None,
            },
        )?;
        line.value(WIFI, self.ssid.as_deref().map(Ssid))?;
        line.value(
            WIFI_KEY,
            self.wifi_key
                .as_deref()
                .filter(|&path| path != DEFAULT_WIFI_KEY),
        )?;
        line.value(WIFI_COUNTRY, self.wifi_country.as_deref())?;
        line.value(WIFI_PREFER, self.wifi_prefer.as_deref().map(Ssid))?;
        line.value(IPV4, self.ipv4)?;
        line.value(IPV4_GATEWAY, self.ipv4_gateway)?;
        line.value(DNS, (!self.dns.is_empty()).then(|| Servers(&self.dns)))?;
        line.flag("--input", self.input)?;
        line.value(TRACKPAD, self.trackpad.map(GuestTrackpad::name))?;
        line.flag(BLUETOOTH_LEND, self.bluetooth_lend)?;
        line.flag(BLUETOOTH_TRACE, self.bluetooth_trace)?;
        line.flag("--idle-skip", self.idle_skip)?;
        line.flag("--survey", self.survey)?;
        line.flag("--sep-observe", self.sep_observe)?;
        line.value(NATIVE_CORES, self.native_cores)?;
        line.value(GUEST_PES, self.guest_pes)?;
        line.value(CODE_WINDOW, self.code_window)?;
        line.flag(NO_IBPB, self.no_ibpb)?;
        line.value(TIMER_DELAY, self.timer_delay)?;
        line.value(
            DISPLAY_SIZE,
            self.display_size
                .map(|(width, height)| alloc::format!("{width}x{height}")),
        )?;
        line.flag("--native-rounds", self.native_rounds)?;
        line.flag("--native-artifacts", self.native_artifacts)?;
        line.flag("--native-bootstrap-check", self.native_bootstrap_check)?;
        line.flag("--native-shared-check", self.native_shared_check)?;
        let implied_serial =
            self.native_rounds || self.native_shared_check || self.native_bootstrap_check;
        line.flag("--serialized", !self.parallel && !implied_serial)?;
        line.flag("--profile", self.profile)?;
        line.value("--lid", self.lid.map(Lid::name))?;
        line.flag("--lid-sleep", self.lid_sleep)?;
        line.flag("--brightness-keys", self.brightness_keys)?;
        line.flag(ACPI_HARDWARE, self.acpi_hardware)?;
        line.value(
            HOST_CORE,
            self.host_core.map(|on| if on { "on" } else { "off" }),
        )?;
        line.flag(KEEP_RUNNING_ON_PANIC, self.keep_running_on_panic)?;
        line.value(
            TLBI_KEEP,
            self.tlbi_keep.map(|keep| if keep { "on" } else { "off" }),
        )?;
        line.flag(TLBI_VERIFY_CHECK, self.tlbi_verify_check)?;
        line.flag(CORE_TRIAL, self.core_trial)?;
        line.value(TIER2, self.tier2.map(|on| if on { "on" } else { "off" }))?;
        line.flag(TIER2_CHECK, self.tier2_check)?;
        line.value(
            PACK_PRELOAD,
            self.pack_preload.map(|on| if on { "on" } else { "off" }),
        )?;
        line.flag(STORE_ESP, self.store_esp)?;
        line.value(LAPTOP, self.laptop.map(Laptop::name))?;
        line.value(
            HYBRID_SCANOUT,
            self.hybrid_scanout.map(|on| if on { "on" } else { "off" }),
        )?;
        line.value(ASUS_MODE, self.asus_mode.map(AsusMode::name))?;
        line.value(GPU_ASPM, self.gpu_aspm.map(GpuAspm::name))?;
        line.value(AMX_NATIVE, self.amx_native)?;
        line.flag("--hle", self.hle)?;
        line.value(
            "--hle-off",
            (!self.hle_off.is_empty()).then(|| Routines(&self.hle_off)),
        )?;
        line.flag("--monitor-trace", self.monitor_trace)?;
        line.flag("--display-trace", self.display_trace)?;
        line.value("--network-check", self.network_check.as_deref())?;
        line.value("--audio-check", self.audio_check.map(AudioCheck::name))?;
        line.flag("--audio-own-hpet", self.audio_own_hpet)?;
        line.flag("--native-pci-own-ioapic", self.native_pci_own_ioapic)?;
        if self.dram_explicit {
            line.value("--dram-base", Some(Hex(self.dram_base)))?;
        }
        for (name, value, default) in [
            ("--load", self.load, DRAM_BASE),
            ("--entry", self.entry, DRAM_BASE),
            ("--x0", self.x0, 0),
            ("--budget", self.budget, 0),
        ] {
            if value != default {
                line.value(name, Some(Hex(value)))?;
            }
        }
        for &address in &self.breakpoints {
            line.value("--break", Some(Hex(address)))?;
        }
        for &address in &self.traces {
            line.value("--trace", Some(Hex(address)))?;
        }
        for &(base, bytes) in &self.watches {
            write!(line.0, " --watch {base:#x},{bytes:#x}")?;
        }
        for &(base, bytes) in &self.dumps {
            write!(line.0, " --dump {base},{bytes:#x}")?;
        }
        Ok(())
    }
}

pub const HOST_CHECK: &str = "--host-check";
const DEFAULT_KEY_SECONDS: u64 = 60;

/// The options of a `--host-check` line: the standalone report on the PC
/// and its diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCheck {
    /// Read the NOR image from this FAT32 partition's file (`--nor-file
    /// GUID:/PATH`).
    pub nor_file: Option<(Guid, String)>,
    /// Start only the xHCI of a Realtek USB Bluetooth controller, bring the
    /// controller up with the USB stick's firmware and scan through it
    /// (`--bluetooth-check`).
    pub bluetooth_check: bool,
    /// Stop after this many seconds (`--deadline`).
    pub deadline: Option<u64>,
    /// How long a prompt waits for a key (`--key-seconds`).
    pub key_seconds: u64,
    /// Keep the newest lines, the summary among them, in the firmware's
    /// stop-record variables once the checks end (`--keep-lines`).
    pub keep_lines: bool,
}

impl Default for HostCheck {
    fn default() -> Self {
        Self {
            nor_file: None,
            bluetooth_check: false,
            deadline: None,
            key_seconds: DEFAULT_KEY_SECONDS,
            keep_lines: false,
        }
    }
}

fn seconds(value: Option<&str>) -> Result<u64, Error> {
    value
        .and_then(|value| value.parse().ok())
        .filter(|&seconds| seconds > 0)
        .ok_or(Error::HostSeconds)
}

impl HostCheck {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut words = text.split_ascii_whitespace();
        if words.next() != Some(HOST_CHECK) {
            return Err(Error::HostPrefix);
        }
        let mut options = Self::default();
        while let Some(word) = words.next() {
            match word {
                "--nor-file" => {
                    let (guid, path) = words
                        .next()
                        .and_then(|value| value.split_once(':'))
                        .ok_or(Error::HostNorSpecification)?;
                    options.nor_file = Some((
                        guid.parse().map_err(|source| Error::Guid {
                            argument: GuidArgument::HostNorFile,
                            source,
                        })?,
                        String::from(path),
                    ));
                }
                "--bluetooth-check" => options.bluetooth_check = true,
                "--deadline" => options.deadline = Some(seconds(words.next())?),
                "--key-seconds" => options.key_seconds = seconds(words.next())?,
                "--keep-lines" => options.keep_lines = true,
                _ => return Err(Error::UnknownHostOption),
            }
        }
        Ok(options)
    }
}

impl fmt::Display for HostCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(HOST_CHECK)?;
        let mut line = Line(f);
        if let Some((guid, path)) = &self.nor_file {
            write!(line.0, " --nor-file {guid}:{path}")?;
        }
        line.flag("--bluetooth-check", self.bluetooth_check)?;
        line.value("--deadline", self.deadline)?;
        if self.key_seconds != DEFAULT_KEY_SECONDS {
            line.value("--key-seconds", Some(self.key_seconds))?;
        }
        line.flag("--keep-lines", self.keep_lines)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;

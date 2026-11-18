//! PCI functions whose drivers attach through [`NativeServices`]: each takes
//! a stopped requester, its DMA domain and owned BAR mappings from the mount.
use super::{Error, NativeServices, ServiceError};
#[cfg(feature = "native-acpi")]
use crate::net::wifi;
use crate::{
    Clock,
    bluetooth::{bcm4377, intel_pcie},
    bus::{
        dma::{DomainAllocator, mapping::DmaDomain, memory::PageSource},
        mmio::owned::{CacheAttribute, Mapping, Protection},
        pci::{
            Address, Bar, ConfigSpace, Function,
            msix::MappedBar,
            owned::OwnedConfig,
            requester::preparation::{
                Attachment, Failure as PreparationFailure, PreparingRequester,
            },
        },
        vmd,
    },
    net::{
        Link, LinkError, Mac,
        aqtion::{self, MappedRegisters},
        tg3,
        wifi::{
            mediatek,
            realtek::{
                self as realtek_wifi,
                ax::{
                    AttachError, AxError, AxIo, BringUpError, FirmwareFile, Host, Live, NativeAxIo,
                    Rings, Running, Wifi, bring_up, elements::phy_tables, phy::check_tables,
                    quiesce,
                },
            },
        },
    },
    storage::nvme,
    usb::ehci,
};
use alloc::{boxed::Box, rc::Rc, string::String, sync::Arc, vec::Vec};
use core::{any::Any, cell::RefCell};

pub mod hda;
pub mod usb4;

/// A Broadcom Tigon3 adapter over owned BAR0 and APE mappings.
pub type Tg3 = tg3::Packet<tg3::io::Mmio<OwnedConfig>, Rc<dyn crate::bus::pci::power::Timer>>;

/// A link driver and the PCI location it was found at.
pub struct Located<L> {
    pub location: String,
    pub link: L,
}

impl<L: Link> Link for Located<L> {
    fn mac(&self) -> Mac {
        self.link.mac()
    }
    fn carrier(&mut self) -> bool {
        self.link.carrier()
    }
    fn carrier_wait_us(&self) -> u64 {
        self.link.carrier_wait_us()
    }
    fn signals(&self) -> bool {
        self.link.signals()
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.link.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        self.link.receive()
    }
    /// The driver's own state line, which the adapter reports only for the
    /// drivers it names (`probe.rs` `Adapter::diagnostic`).
    fn diagnostic(&mut self) -> Option<String> {
        self.link.diagnostic()
    }
}

/// The drivers here that attach through [`NativeServices`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Tg3,
    Aqtion,
    Vmd,
    /// AMD Sensor Fusion Hub v2.
    Sfh,
    /// Intel Integrated Sensor Hub.
    Ish,
    /// An Intel Wi-Fi function, which `iwl_pci_probe` identifies further.
    IntelWifi,
    /// A MediaTek Wi-Fi function; only MT7925 attaches.
    MediatekWifi,
    /// A Realtek Wi-Fi function; only RTL8822C attaches.
    RealtekWifi,
    /// An RTL8852CE, attached as a station kept connected to the `--wifi`
    /// network.
    Rtw89Wifi,
    /// An Intel PCIe Bluetooth function, as `btintel_pcie_table` lists them.
    IntelBluetooth,
    /// A Broadcom PCIe Bluetooth function, as `bcm4377_devid_table` lists
    /// them.
    Bcm4377,
    /// An HD Audio controller the bounded identity table admits.
    Hda,
    /// A USB4/Thunderbolt host interface, as `pci.c::nhi_ids` lists them.
    Usb4,
}

impl Kind {
    pub(super) fn of(function: &Function) -> Option<Self> {
        Self::of_identity(&function.identity())
    }

    /// [`Self::of`] from a function's copied header fields.
    pub(super) fn of_identity(function: &crate::bus::pci::Identity) -> Option<Self> {
        if vmd::Profile::identify(function.vendor, function.device).is_ok() {
            Some(Self::Vmd)
        } else if tg3::candidate(function.vendor, function.device, function.class) {
            Some(Self::Tg3)
        } else if aqtion::Profile::identify(function.vendor, function.device).is_some()
            && function.class == [2, 0, 0]
        {
            Some(Self::Aqtion)
        } else if (function.vendor, function.device) == (0x1022, 0x15e4) {
            Some(Self::Sfh)
        } else if (function.vendor, function.device) == (0x8086, 0x9d35) {
            Some(Self::Ish)
        } else if function.vendor == 0x8086 && function.class[..2] == [2, 0x80] {
            Some(Self::IntelWifi)
        } else if function.vendor == 0x14c3 && function.class[..2] == [2, 0x80] {
            Some(Self::MediatekWifi)
        } else if function.vendor == 0x10ec
            && function.class[..2] == [2, 0x80]
            && realtek_wifi::identity::RTL8822C_DEVICES.contains(&function.device)
        {
            Some(Self::RealtekWifi)
        } else if function.vendor == 0x10ec
            && function.class[..2] == [2, 0x80]
            && function.device == RTL8852CE_DEVICE
        {
            Some(Self::Rtw89Wifi)
        } else if function.vendor == 0x8086 && intel_pcie::DEVICE_IDS.contains(&function.device) {
            Some(Self::IntelBluetooth)
        } else if function.vendor == 0x14e4
            && function.class[..2] == [2, 0x80]
            && bcm4377::Chip::of_device(function.device).is_some()
        {
            Some(Self::Bcm4377)
        } else if crate::audio::hda::pci::identify_identity(function).is_ok() {
            Some(Self::Hda)
        } else if crate::bus::thunderbolt::controller::Profile::identify(
            function.vendor,
            function.device,
            u32::from_be_bytes([0, function.class[0], function.class[1], function.class[2]]),
        )
        .is_ok()
        {
            Some(Self::Usb4)
        } else {
            None
        }
    }

    /// The driver this kind attaches with, as the boot log names it.
    pub(super) fn driver(self) -> &'static str {
        match self {
            Self::Tg3 => "tg3 Ethernet",
            Self::Aqtion => "atlantic Ethernet",
            Self::Vmd => "Intel VMD storage",
            Self::Sfh => "AMD sensor hub",
            Self::Ish => "Intel sensor hub",
            Self::IntelWifi => "iwlwifi Wi-Fi (with --wifi)",
            Self::MediatekWifi => "mt7925 Wi-Fi (with --wifi)",
            Self::RealtekWifi => "rtw88 Wi-Fi (with --wifi)",
            Self::Rtw89Wifi => "rtw89 Wi-Fi (with --wifi)",
            Self::IntelBluetooth => "Intel PCIe Bluetooth",
            Self::Bcm4377 => "bcm4377 Bluetooth",
            Self::Hda => "HD Audio",
            Self::Usb4 => "USB4/Thunderbolt NHI",
        }
    }
}

/// A PCI bridge the scan passed.
#[derive(Clone, Copy, Debug)]
pub(super) struct Bridge {
    pub(super) address: Address,
    pub(super) secondary: u8,
    /// The ASPM Control field of its PCIe Link Control.
    pub(super) aspm: u16,
}

/// The bridge whose secondary bus is `bus`: Linux's `bus->self`.
fn upstream(bridges: &[Bridge], segment: u16, bus: u8) -> Option<&Bridge> {
    bridges.iter().find(|bridge| {
        bridge.address.segment == segment && bridge.secondary == bus && bridge.address.bus < bus
    })
}

/// `mt76_pci_aspm_supported`: whether firmware enabled ASPM on the
/// function's link, at either end.
pub(super) fn aspm_supported<C: ConfigSpace>(
    function: &Function<C>,
    bridges: &[Bridge],
) -> Result<bool, crate::block::BlockError> {
    let address = function.address;
    Ok(crate::bus::pci::aspm_control(function)? != 0
        || upstream(bridges, address.segment, address.bus).is_some_and(|parent| parent.aspm != 0))
}

fn mediatek_identity<C: ConfigSpace>(
    function: &mut Function<C>,
) -> Result<mediatek::identity::PciIdentity, crate::bus::pci::ConfigError> {
    let (vendor, device) = (function.vendor, function.device);
    let config = function.config();
    Ok(mediatek::identity::PciIdentity {
        vendor,
        device,
        subsystem_vendor: config.read16(0x2c)?,
        subsystem_device: config.read16(0x2e)?,
        revision: config.read8(0x08)?,
    })
}

/// A function claimed from the mount, before any device effect.
struct Claimed {
    function: Function<OwnedConfig>,
    domain: Arc<dyn DmaDomain>,
    bars: [Option<Bar>; 6],
}

#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
fn claim(services: &dyn NativeServices, address: Address) -> Result<Claimed, Failure> {
    // The Wi-Fi drivers set Bus Master before they reset their engines, so
    // they produce no quiescence receipt yet: the function stays unmastered,
    // and the seal refuses that write.
    let requester = super::services::claim_unmastered(services, address)
        .map_err(|error| (Error::Native(error), None))?;
    let (requester, binding) = match requester.into_dma_binding() {
        Ok(value) => value,
        Err((error, owner)) => {
            return Err(keep_error(Error::Native(ServiceError::Claim(error)), owner));
        }
    };
    let domain = match services.domain(binding) {
        Ok(domain) => domain,
        Err(error) => return Err(keep_error(Error::Native(error), requester)),
    };
    let mut function = requester.into_function();
    let bars = match function.bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, (function, domain))),
    };
    Ok(Claimed {
        function,
        domain,
        bars,
    })
}

fn map(
    services: &dyn NativeServices,
    address: Address,
    bars: &[Option<Bar>; 6],
    index: usize,
) -> Result<Mapping, ServiceError> {
    match bars[index] {
        Some(bar @ Bar::Memory { .. }) => services.map_bar(address, bar),
        _ => Err(ServiceError::Refused("missing memory BAR")),
    }
}

/// What a failed attach leaves: the error and any owner that must outlive
/// the device because it may hold mappings or DMA.
pub(super) type Failure = (Error, Option<Box<dyn Any>>);

fn keep_error(error: impl Into<Error>, owner: impl Any) -> Failure {
    (error.into(), Some(Box::new(owner)))
}

/// Attach an EHCI host controller with its own requester, BAR0 and DMA arena.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, `clock` is the
/// handoff's calibrated clock, and every companion controller of its roots
/// completed the legacy handoff. This path takes the EHCI BIOS semaphore
/// through the original requester and register owners.
#[expect(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn ehci(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<ehci::host::Shared, Failure> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    let refused = |error: ServiceError| (Error::Native(error), None);
    let mut requester = services.prepare_requester(address).map_err(refused)?;
    let bars = match requester.function_mut().bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, requester)),
    };
    let registers = match map(services, address, &bars, 0) {
        Ok(registers) => registers,
        Err(error) => return Err(keep_error(Error::Native(error), (requester, minimum))),
    };
    let resources = ehci::NativeResources {
        requester,
        registers,
        memory: services.pages(),
        clock,
        minimum,
    };
    // SAFETY: paired original configuration/root/BAR owners and masked/drained
    // IRQ/work exclusion from the cold mount grant. The caller owns the
    // companions. EHCI proves BIOS release and engine HALT, then drains the
    // original root before binding the domain or allocating its arena.
    match unsafe { ehci::attach(resources) } {
        Ok((controller, _)) => Ok(Rc::new(RefCell::new(controller))),
        Err(failure) => Err((Error::Ehci(failure.error), Some(Box::new(failure)))),
    }
}

/// Attach a Tigon3 adapter: BAR0 holds the MAC registers, BAR2 the APE
/// of a chip that has one.
///
/// # Safety
/// [`NativeServices`]' contract holds for `services`, and `clock` is the
/// handoff's calibrated clock.
#[expect(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn tg3(
    services: &dyn NativeServices,
    address: Address,
) -> Result<Located<Tg3>, Failure> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    let refused = |error: ServiceError| (Error::Native(error), None);
    let mut requester = services.prepare_requester(address).map_err(refused)?;
    let bars = match requester.function_mut().bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, requester)),
    };
    let mac = match map(services, address, &bars, 0) {
        Ok(mac) => mac,
        Err(error) => return Err(keep_error(Error::Native(error), (requester, minimum))),
    };
    // Only a chip with an APE has BAR 2 (Linux maps it for those alone).
    let ape = if tg3::ape(requester.function_mut().device) {
        match map(services, address, &bars, 2) {
            Ok(ape) => Some(ape),
            Err(error) => return Err(keep_error(Error::Native(error), (requester, mac, minimum))),
        }
    } else {
        None
    };
    let window = |mapping: &Mapping| {
        let bytes = mapping.bytes()?;
        Ok((mapping.address(0, bytes)?, bytes))
    };
    let ((mac_window, mac_bytes), ape_window) =
        match window(&mac).and_then(|mac| Ok((mac, ape.as_ref().map(window).transpose()?))) {
            Ok(windows) => windows,
            Err(error) => {
                return Err(keep_error(
                    Error::Native(ServiceError::Mapping(error)),
                    (requester, mac, ape, minimum),
                ));
            }
        };
    let windows: Arc<dyn Any> = Arc::new((mac, ape));
    // SAFETY: original preparation keeps configuration/root/inherited backing
    // and prior IRQ/work exclusions. Both UC mappings belong to that function.
    let registers = unsafe {
        tg3::io::Cold::from_owned_windows(requester, mac_window, mac_bytes, ape_window, windows)
    }
    .map_err(|(error, requester, windows)| {
        (
            Error::Tg3(error),
            Some(Box::new((requester, windows)) as Box<dyn Any>),
        )
    })?;
    // SAFETY: the cold registers meet their exclusive native ownership
    // contract, and this is the handoff's calibrated clock/context.
    let hardware = unsafe { tg3::Hardware::new(registers, minimum.clone()) };
    let registers = hardware.quiesce_cold().map_err(|(error, hardware)| {
        (Error::Tg3(error), Some(Box::new(hardware) as Box<dyn Any>))
    })?;
    // SAFETY: quiesce_cold acknowledged this original function's vendor
    // engines and BME stop. No IRQ/work or competing config/reset owner exists.
    // Binding first drains the old root while all original windows stay kept.
    let bound = unsafe { registers.bind() }.map_err(|failure| {
        (
            Error::Tg3(tg3::Error::Preparation(failure.error)),
            Some(Box::new(failure) as Box<dyn Any>),
        )
    })?;
    // SAFETY: finalization preserved these exact register owners and supplies
    // their isolated domain/unique attachment. No DMA allocation occurred yet.
    let hardware = unsafe { tg3::Hardware::new(bound.registers, minimum.clone()) };
    // SAFETY: original-root drain and current-epoch binding completed; IRQ/work
    // exclusions stay held. Packet retirement unmaps rings before detaching.
    match unsafe { tg3::Packet::attach_bound(hardware, services.pages(), bound.attachment) } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err((error, link)) => Err((Error::Tg3(error), Some(Box::new(link)))),
    }
}

/// Attach an Aquantia AQtion adapter over its BAR0 registers.
///
/// # Safety
/// As for [`tg3`]. Original configuration/root/backing and prior firmware,
/// IRQ/work and bypass exclusions stay held through cold preparation.
#[expect(
    clippy::result_large_err,
    reason = "failed native attachment returns the original cold or controller owner"
)]
pub(super) unsafe fn aqtion(
    services: &dyn NativeServices,
    address: Address,
) -> Result<Located<aqtion::native::Attached>, Failure> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    let refused = |error: ServiceError| (Error::Native(error), None);
    let mut requester = services.prepare_requester(address).map_err(refused)?;
    let command = match requester
        .function_mut()
        .config()
        .read16(crate::bus::pci::regs::COMMAND)
    {
        Ok(command) => command,
        Err(error) => return Err(keep_error(error, requester)),
    };
    if command == u16::MAX || command & crate::bus::pci::regs::COMMAND_MASTER != 0 {
        return Err((
            Error::Aqtion(aqtion::native::Error::BusMaster(command)),
            Some(Box::new(requester)),
        ));
    }
    // Establish D0 before sizing or mapping the BAR, with bus mastering gated.
    if let Err(error) = requester.function_mut().power_up(minimum.as_ref()) {
        return Err((
            Error::Aqtion(aqtion::native::Error::Power(error)),
            Some(Box::new(requester)),
        ));
    }
    let bars = match requester.function_mut().bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, requester)),
    };
    let registers = map(services, address, &bars, 0).map_err(refused)?;
    let registers = match MappedRegisters::new(registers) {
        Ok(registers) => registers,
        Err((error, mapping)) => {
            return Err((
                Error::Aqtion(aqtion::native::Error::Device(error)),
                Some(Box::new((requester, mapping))),
            ));
        }
    };
    let inputs = aqtion::native::Inputs {
        requester,
        registers,
        timer: minimum,
    };
    // SAFETY: paired original function/root/BAR and calibrated process timer;
    // no Stela IRQ/work or competing writer exists. The driver resets firmware,
    // stops every queue and drains the old root before binding or allocating.
    match unsafe { aqtion::native::attach(inputs, services.pages()) } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err(failure) => Err((
            Error::Aqtion(failure.error.clone()),
            Some(Box::new(failure)),
        )),
    }
}

/// An Intel AX200/AX210 adapter over its owned BAR0, reading its ACPI
/// companion.
#[cfg(feature = "native-acpi")]
pub type IntelWifi = wifi::intel::link::Station<
    wifi::intel::boot::NativeBootIo,
    wifi::intel::radio::bios::service::native::NativeBios,
>;

/// The owners an MT7925 station keeps: its claimed function and BAR0.
pub type MediatekOwner = (
    Function<OwnedConfig>,
    Mapping,
    crate::bus::pci::requester::preparation::Attachment,
);

/// An MT7925 station over its owned function and BAR0.
pub type MediatekWifi = mediatek::station::Wifi<MediatekOwner>;

/// Attach a MediaTek Wi-Fi function: BAR0 holds its registers and remap
/// windows.
///
/// # Safety
/// As for [`tg3`]; `inputs` describes this function's own link and ACPI
/// companion.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn mediatek_wifi(
    services: &dyn NativeServices,
    address: Address,
    completion: Option<crate::bus::irq::MsiMessage>,
    mut inputs: mediatek::attach::Inputs,
) -> Result<Located<mediatek::attach::Attached<MediatekOwner>>, Failure> {
    let refused = |error: ServiceError| (Error::Native(error), None);
    let minimum = services.minimum_delay().map_err(refused)?;
    let mut requester = services.prepare_requester(address).map_err(refused)?;
    if let Err(error) = requester.function_mut().power_up(minimum.as_ref()) {
        return Err(keep_error(error, requester));
    }
    let pci = match mediatek_identity(requester.function_mut()) {
        Ok(pci) => pci,
        Err(error) => return Err(keep_error(error, requester)),
    };
    // MT7925 has no FLR or PM reset (Linux's reset_method is `bus` alone), so
    // a Secondary Bus Reset of its port is what stops every engine firmware
    // left, as the GPU cold path does. Without one it is refused.
    let reset = (|| -> Result<(), Error> {
        if !requester.bus_reset_available() {
            return Err(Error::Native(ServiceError::Refused(
                "MT7925 has no function reset and its bus cannot be reset",
            )));
        }
        requester.reset_bus(minimum.as_ref())?;
        crate::bus::pci::requester::validate_stopped(requester.function_mut())
            .map_err(|error| Error::Native(ServiceError::Claim(error)))
    })();
    if let Err(error) = reset {
        return Err(keep_error(error, requester));
    }
    // SAFETY: the bus reset above stopped every engine of this function and
    // its stopped state was revalidated; no Stela submission, IRQ or work
    // exists yet. Finalization drains the original root before binding.
    let bound = match unsafe { requester.acknowledge_quiescence() }.finalize() {
        Ok(bound) => bound,
        Err(failure) => {
            return Err((Error::Preparation(failure.error.clone()), Some(Box::new(failure))));
        }
    };
    let domain = bound.attachment.domain();
    let attachment = bound.attachment;
    let mut function = bound.requester.into_function();
    let bars = match function.bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, (function, attachment))),
    };
    let registers = match map(services, address, &bars, 0) {
        Ok(registers) => registers,
        Err(error) => return Err(keep_error(Error::Native(error), (function, attachment))),
    };
    let (base, bytes) = match registers
        .bytes()
        .and_then(|bytes| Ok((registers.address(0, bytes)?, bytes)))
    {
        Ok(window) => window,
        Err(error) => {
            return Err(keep_error(
                Error::Native(ServiceError::Mapping(error)),
                (function, attachment, registers),
            ));
        }
    };
    let configured = (|| -> Result<bool, Error> {
        let interrupt = function.interrupts()?.msi;
        function.enable_polled()?;
        match (completion, interrupt) {
            (Some(message), Some(msi)) => {
                function.enable_msi(msi, message)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    })();
    inputs.vector = match configured {
        Ok(vector) => vector,
        Err(error) => return Err(keep_error(error, (function, attachment, registers))),
    };
    #[expect(
        clippy::arc_with_non_send_sync,
        reason = "The serialized BAR and queue retainers require Arc<dyn Any>; this PCI custody remains !Send and !Sync."
    )]
    let owner = Arc::new((function, registers, attachment));
    let kept = Box::new(owner.clone()) as Box<dyn Any>;
    // SAFETY: the mount claimed the stopped function, mapped its BAR0
    // uncached and supplied an isolating domain; `owner` keeps the function
    // and mapping, and its interrupts are off.
    match unsafe { mediatek::attach::attach(pci, base.cast(), bytes, owner, domain, inputs) } {
        Ok(attached) => Ok(Located {
            location: alloc::format!("{address}"),
            link: attached,
        }),
        Err(error) => Err((Error::MediatekWifi(error), Some(kept))),
    }
}

/// An RTL8822C station on its hardware.
pub type RealtekWifi = realtek_wifi::station::Wifi<realtek_wifi::hardware::Hardware>;

/// Attach an RTL8822C: `rtw_pci_io_mapping` finds its registers in BAR2.
///
/// # Safety
/// As for [`tg3`].
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn realtek_wifi(
    services: &dyn NativeServices,
    address: Address,
    completion: Option<crate::bus::irq::MsiMessage>,
    mut inputs: realtek_wifi::attach::Inputs,
) -> Result<Located<RealtekWifi>, Failure> {
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address)?;
    let registers = match map(services, address, &bars, 2) {
        Ok(registers) => registers,
        Err(error) => return Err(keep_error(Error::Native(error), (function, domain))),
    };
    let (base, bytes) = match registers
        .bytes()
        .and_then(|bytes| Ok((registers.address(0, bytes)?, bytes)))
    {
        Ok(window) => window,
        Err(error) => {
            return Err(keep_error(
                Error::Native(ServiceError::Mapping(error)),
                (function, domain, registers),
            ));
        }
    };
    let configured = (|| -> Result<_, Error> {
        let link_control = crate::bus::pci::link_control_word(&function)?;
        let config = function.config();
        let identity = (
            config.read16(0x2c)?,
            config.read16(0x2e)?,
            config.read8(0x08)?,
        );
        let interrupt = function.interrupts()?.msi;
        function.enable_polled()?;
        let vector = match (completion, interrupt) {
            (Some(message), Some(msi)) => {
                function.enable_msi(msi, message)?;
                true
            }
            _ => false,
        };
        Ok((link_control, identity, vector))
    })();
    let (link_control, (subsystem_vendor, subsystem_device, pci_revision), vector) =
        match configured {
            Ok(configured) => configured,
            Err(error) => return Err(keep_error(error, (function, domain, registers))),
        };
    inputs.link_control = link_control;
    inputs.vector = vector;
    let observed = realtek_wifi::identity::Observed {
        vendor: function.vendor,
        device: function.device,
        subsystem_vendor,
        subsystem_device,
        pci_revision,
        // SAFETY: same owned mapped BAR2, whose first page holds SYS_CFG1.
        sys_cfg1: unsafe { crate::bus::mmio::Mmio::new(base.as_ptr() as u64, 4096) }.read32(0xf0),
    };
    #[expect(
        clippy::arc_with_non_send_sync,
        reason = "The serialized Realtek backend retains Arc<dyn Any>; this PCI custody remains !Send and !Sync."
    )]
    let owner: Arc<dyn Any> = Arc::new((function, registers));
    let kept = Box::new(owner.clone()) as Box<dyn Any>;
    // SAFETY: the mount claimed the stopped function, mapped its BAR2 uncached
    // and supplied an isolating domain; `owner` keeps the function and mapping,
    // and the device's interrupt masks are off until the station starts.
    match unsafe {
        realtek_wifi::attach::attach(base.cast(), bytes, owner, domain, observed, inputs)
    } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err(error) => Err((Error::RealtekWifi(error), Some(kept))),
    }
}

/// `rtw8852ce_id_table`'s one device (`rtw8852ce.c`).
const RTL8852CE_DEVICE: u16 = 0xc852;

/// An RTL8852CE station on its hardware: the live chip over its BAR2 window,
/// kept connected to the `--wifi` network.
pub type Rtw89Wifi = Wifi<Live<NativeAxIo>>;

/// What an RTL8852CE station needs of the machine around it.
pub struct Rtw89Inputs {
    pub firmware: &'static dyn crate::firmware::Provider,
    pub pages: &'static dyn PageSource,
    pub clock: Clock,
    /// regulatory.db, which holds the network's country, or the world's
    /// `00` when it names none.
    pub database: crate::net::wifi::regulatory::database::Database,
    pub network: crate::net::wifi::network::Network,
    /// The source of the station's handshake nonces.
    pub entropy: Arc<dyn crate::entropy::Entropy>,
}

/// An RTL8852CE whose station attach failed.
pub struct Rtw89Down {
    pub error: Error,
    /// As [`Rtw89Up::was_on`]: whether its MAC had been left on, and so was
    /// powered off, before the failure.
    pub was_on: bool,
    /// Whatever must outlive the device once claimed: its requester and
    /// domain, its BAR2 mapping and register window, and any rings.
    pub kept: Option<Box<dyn Any>>,
    /// Why Bus Master could not be cleared again after the failure, when
    /// it could not (`Rtw89Keep::unmaster`).
    pub bus_master: Option<Error>,
}

impl From<Failure> for Rtw89Down {
    fn from((error, kept): Failure) -> Self {
        Self {
            error,
            was_on: false,
            kept,
            bus_master: None,
        }
    }
}

/// An RTL8852CE whose station runs.
pub struct Rtw89Up {
    /// The station, kept connected to the network, and where it was found.
    pub station: Located<Rtw89Wifi>,
    /// What its bring-up reported.
    pub running: Running,
    /// Whether firmware or an earlier driver had left its MAC on, so it was
    /// powered off before its requester was taken over.
    pub was_on: bool,
    /// Its requester and bound domain, kept for the rest of the boot; the
    /// station owns the register window (and with it BAR2's mapping), the
    /// rings and the TX pools.
    pub kept: Box<dyn Any>,
}

/// Attach an RTL8852CE as a station kept connected to `inputs.network`
/// (M3 spec S16.2): `rtw89_pci_setup_mapping` finds its registers in BAR2,
/// and [`rtw89_keep`] runs the station's attach where M2c's bring-up ran.
/// The requester is taken through the mount's cold preparation and brought
/// to D0 there ([`rtw89_wake`]), so Bus Master stays sealed off until the
/// chip is quiesced and its own domain is bound ([`rtw89_attach_with`]).
/// Every failure leaves Bus Master clear and the chip either untouched
/// (before its quiescence, or in LPS or an undefined state) or powered off,
/// and keeps whatever DMA could still reach.
///
/// # Safety
/// As for [`tg3`].
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn rtw89_wifi(
    services: &dyn NativeServices,
    address: Address,
    inputs: Rtw89Inputs,
) -> Result<Rtw89Up, Rtw89Down> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    let refused = |error: ServiceError| (Error::Native(error), None);
    let mut preparing = services.prepare_requester(address).map_err(refused)?;
    let bars = match rtw89_wake(preparing.function_mut(), minimum.as_ref()) {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, preparing).into()),
    };
    // A BAR is mapped during preparation, before any binding, as Intel's
    // PCIe Bluetooth maps its BAR0: the mapping grants register access only,
    // and the seal still holds Bus Master clear.
    let registers = match map(services, address, &bars, 2) {
        Ok(registers) => registers,
        Err(error) => return Err(keep_error(Error::Native(error), preparing).into()),
    };
    let (base, bytes) = match registers
        .bytes()
        .and_then(|bytes| Ok((registers.address(0, bytes)?, bytes)))
    {
        Ok(window) => window,
        Err(error) => {
            return Err(keep_error(
                Error::Native(ServiceError::Mapping(error)),
                (preparing, registers),
            )
            .into());
        }
    };
    let (subsystem_vendor, subsystem_device, pci_revision, host) =
        match rtw89_decode(preparing.function_mut()) {
            Ok(identity) => identity,
            Err(error) => return Err(keep_error(error, (preparing, registers)).into()),
        };
    let (vendor, device) = {
        let function = preparing.function_mut();
        (function.vendor, function.device)
    };
    let mapping: Arc<dyn Any> = Arc::new(registers);
    // SAFETY: the mount mapped BAR2 uncached for this driver alone, `bytes`
    // long, and `mapping` keeps it; `preparing`, then the device owner kept
    // for the rest of the boot, keeps the claim. The probe drives one
    // function at a time, and the handoff's clock is calibrated for this CPU.
    let mut io = match unsafe { NativeAxIo::new(base.cast(), bytes, mapping.clone(), inputs.clock) }
    {
        Ok(io) => io,
        Err(error) => {
            let error = BringUpError::new("register window", error);
            return Err((
                Error::Rtw89Wifi(error),
                Some(Box::new((preparing, mapping)) as Box<dyn Any>),
            )
                .into());
        }
    };
    // SYS_CFG1, with memory decode on: a read only.
    let sys_cfg1 = match io.read32(0xf0) {
        Ok(sys_cfg1) => sys_cfg1,
        Err(error) => {
            let error = BringUpError::new("identity", error);
            return Err(keep_error(Error::Rtw89Wifi(error), (preparing, io)).into());
        }
    };
    let observed = realtek_wifi::identity::Observed {
        vendor,
        device,
        subsystem_vendor,
        subsystem_device,
        pci_revision,
        sys_cfg1,
    };
    let mut device = Rtw89Native {
        claim: Rtw89Claim::Preparing(preparing),
        io: Rtw89Window::Held(io),
        host,
    };
    let Rtw89Inputs {
        firmware,
        pages,
        clock,
        database,
        network,
        entropy,
    } = inputs;
    let station = realtek_wifi::ax::attach::Inputs {
        clock,
        database,
        network,
        entropy,
    };
    // SAFETY: `rtw89_keep`'s contract, which is `rtw89_attach_with`'s:
    // `device.io` is the exclusive UC BAR2 window of the original requester
    // `device.claim` prepares, which the mount parked with Bus Master clear
    // (sealed since) and its outstanding requests drained, under the cold
    // grant that excludes earlier firmware, IRQ and work users and
    // competing writers (`NativeServices`). Its `finalize` is
    // `QuiescenceReceipt::finalize` of that requester, and it keeps BAR2 and
    // every owner of the receipt through each outcome. `pages` is the
    // mount's coherent write-back page source, and the probe drives nothing
    // else meanwhile, nor anything on this function once it returns but
    // the station.
    match unsafe { rtw89_keep(&mut device, observed, firmware, pages, station) } {
        Ok((station, running, was_on)) => Ok(Rtw89Up {
            station: Located {
                location: alloc::format!("{address}"),
                link: station,
            },
            running,
            was_on,
            kept: Box::new(device),
        }),
        // A failure after the rings were programmed left them quarantined;
        // the requester, its domain and BAR2 stay kept.
        Err(Rtw89Refused {
            error,
            was_on,
            rings,
            bus_master,
        }) => Err(Rtw89Down {
            error,
            was_on,
            kept: Some(Box::new((device, rings))),
            bus_master,
        }),
    }
}

/// The register window of an RTL8852CE a station can take
/// ([`rtw89_keep`]): the attach runs on it while it is held, and once taken
/// every access is refused as outside the window and no time passes.
pub(super) enum Rtw89Window<I> {
    Held(I),
    Taken,
}

impl<I> Rtw89Window<I> {
    /// The window, which stays taken until [`Self::put`].
    pub(super) fn take(&mut self) -> Option<I> {
        match core::mem::replace(self, Self::Taken) {
            Self::Held(io) => Some(io),
            Self::Taken => None,
        }
    }

    /// The window handed back.
    pub(super) fn put(&mut self, io: I) {
        *self = Self::Held(io);
    }

    fn held(&mut self, register: u32) -> Result<&mut I, AxError> {
        match self {
            Self::Held(io) => Ok(io),
            Self::Taken => Err(AxError::OutOfWindow { register }),
        }
    }
}

impl<I: AxIo> AxIo for Rtw89Window<I> {
    fn read8(&mut self, reg: u32) -> Result<u8, AxError> {
        self.held(reg)?.read8(reg)
    }
    fn read16(&mut self, reg: u32) -> Result<u16, AxError> {
        self.held(reg)?.read16(reg)
    }
    fn read32(&mut self, reg: u32) -> Result<u32, AxError> {
        self.held(reg)?.read32(reg)
    }
    fn write8(&mut self, reg: u32, v: u8) -> Result<(), AxError> {
        self.held(reg)?.write8(reg, v)
    }
    fn write16(&mut self, reg: u32, v: u16) -> Result<(), AxError> {
        self.held(reg)?.write16(reg, v)
    }
    fn write32(&mut self, reg: u32, v: u32) -> Result<(), AxError> {
        self.held(reg)?.write32(reg, v)
    }
    fn delay_us(&mut self, us: u64) {
        if let Self::Held(io) = self {
            io.delay_us(us);
        }
    }
    fn now_us(&mut self) -> Result<u64, AxError> {
        match self {
            Self::Held(io) => io.now_us(),
            Self::Taken => Err(AxError::Clock),
        }
    }
}

/// An [`Rtw89Device`] a normal boot attaches a station on
/// ([`rtw89_keep`]), which clears Bus Master again when the attach fails.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub(super) trait Rtw89Keep: Rtw89Device {
    /// Bus Master off. A requester never bound is held clear by its
    /// preparation's seal, or by the refused finalization, already.
    fn unmaster(&mut self) -> Result<(), Error>;
}

impl Rtw89Keep for Rtw89Native {
    fn unmaster(&mut self) -> Result<(), Error> {
        match &mut self.claim {
            Rtw89Claim::Bound { function, .. } => Ok(function.set_bus_master(false)?),
            Rtw89Claim::Preparing(_) | Rtw89Claim::Refused { .. } | Rtw89Claim::Finalizing => {
                Ok(())
            }
        }
    }
}

/// Why [`rtw89_keep`] attached no station: the failure, whether the MAC
/// had been on, the rings once they were installed, which DMA may still
/// reach and so are kept, and why Bus Master could not be cleared again,
/// if it could not.
pub(super) struct Rtw89Refused {
    pub error: Error,
    pub was_on: bool,
    pub rings: Option<Rings>,
    pub bus_master: Option<Error>,
}

/// [`rtw89_attach_with`] for a normal boot's `--wifi` network: at step 5
/// the window is taken from `device` and [`realtek_wifi::ax::attach`] runs
/// on it, so the chip stays up as a station kept connected to
/// `inputs.network` (M3 spec S16.1-S16.2). Returns the station, what its
/// bring-up reported ([`realtek_wifi::ax::attach::attach_reporting`]) and
/// whether the MAC was on.
///
/// A failure is the step's, as [`rtw89_attach_with`]'s are: before step 5
/// the chip was never powered on, or a MAC left on was powered off; at
/// step 5 the attach either refused before any register access, powered
/// the chip off after a failed start, or stopped it after it started. A
/// bring-up step's failure stays an `Error::Rtw89Wifi`, and the station's
/// own an `Error::Rtw89Station`. The window goes back to `device`, the rings
/// are returned, and then Bus Master is cleared ([`Rtw89Keep::unmaster`]),
/// whatever failed, so the function issues nothing after.
///
/// # Safety
/// As for [`rtw89_attach`], for as long as the station runs: nothing but the
/// station drives the function once this returns it.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub(super) unsafe fn rtw89_keep<D, I>(
    device: &mut D,
    observed: realtek_wifi::identity::Observed,
    firmware: &dyn crate::firmware::Provider,
    pages: &dyn PageSource,
    inputs: realtek_wifi::ax::attach::Inputs,
) -> Result<(Wifi<Live<I>>, Running, bool), Rtw89Refused>
where
    D: Rtw89Keep<Io = Rtw89Window<I>> + ?Sized,
    I: AxIo,
{
    let mut quarantined = None;
    #[expect(
        clippy::result_large_err,
        reason = "rtw89_attach_with's step 5 returns the probe's own error, as bring_up's does."
    )]
    let station = |window: &mut Rtw89Window<I>,
                   pages: &dyn PageSource,
                   domain: Arc<dyn DmaDomain>,
                   cut: u8,
                   file: FirmwareFile<'_>,
                   host: Host| {
        let io = window.take().ok_or(Error::Rtw89Wifi(BringUpError::new(
            "register window",
            AxError::OutOfWindow { register: 0 },
        )))?;
        // SAFETY: `rtw89_attach_with` runs this at step 5 with `bring_up`'s
        // contract holding for the window, `pages` and `domain`, and
        // `attach_reporting`'s contract is that one (`live::start`'s); this
        // function's caller keeps it for as long as the station runs, whose
        // window this is from here on.
        let attached = unsafe {
            realtek_wifi::ax::attach::attach_reporting(io, pages, domain, cut, file, host, inputs)
        };
        attached.map_err(|(error, returned)| {
            if let Some((io, rings)) = returned {
                window.put(io);
                quarantined = rings;
            }
            match error {
                AttachError::Start(error) => Error::Rtw89Wifi(error),
                error => Error::Rtw89Station(error),
            }
        })
    };
    // SAFETY: this function's contract is `rtw89_attach_with`'s.
    let attached = unsafe { rtw89_attach_with(device, observed, firmware, pages, station) };
    match attached {
        Ok(((wifi, running), was_on)) => Ok((wifi, running, was_on)),
        Err((error, was_on)) => Err(Rtw89Refused {
            error,
            was_on,
            rings: quarantined,
            bus_master: device.unmaster().err(),
        }),
    }
}

/// Restore D0 under preparation, then size the BARs, as the attaches of
/// Intel's PCIe Bluetooth and bcm4377 do: a chip firmware left in D3hot then
/// answers its registers, and the BARs a D3hot soft reset cleared are
/// written back before they are sized. Bus Master stays sealed clear.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
fn rtw89_wake<C: ConfigSpace>(
    function: &mut Function<C>,
    minimum: &dyn crate::bus::pci::power::Timer,
) -> Result<[Option<Bar>; 6], Error> {
    function.power_up(minimum)?;
    Ok(function.bars()?)
}

/// The RTL8852CE's subsystem IDs and revision, and the [`Host`] its
/// bring-up runs under, then memory decode on with MSI, MSI-X and INTx off
/// and Bus Master left clear: what reading BAR2 during preparation needs,
/// and nothing the preparation's seal refuses.
///
/// `Host::ltr` is `rtw89_pci_dev_ltr_enabled` (`pci.c:3042`): DEVCTL2
/// `PCI_EXP_DEVCTL2_LTR_EN` (bit 10 of PCIe capability + 0x28). Linux's
/// `pcie_capability_read_word` gives 0 for a function with no PCIe
/// capability, or with a version 1 one, which has no DEVCTL2
/// (`pcie_capability_reg_implemented`, `drivers/pci/access.c`); so does
/// this. Nothing in Stela writes DEVCTL2 between this read and the
/// bring-up's post-init, where Linux reads it (spec S1.8).
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
fn rtw89_decode<C: ConfigSpace>(function: &mut Function<C>) -> Result<(u16, u16, u8, Host), Error> {
    /// `PCI_CAP_ID_EXP`, `PCI_EXP_FLAGS_VERS`, `PCI_EXP_DEVCTL2` and
    /// `PCI_EXP_DEVCTL2_LTR_EN` (`include/uapi/linux/pci_regs.h`).
    const CAP_ID_EXP: u8 = 0x10;
    const EXP_FLAGS_VERS: u16 = 0x000f;
    const EXP_DEVCTL2: u16 = 0x28;
    const EXP_DEVCTL2_LTR_EN: u16 = 1 << 10;
    let express = function
        .capabilities()?
        .into_iter()
        .find(|&(_, id)| id == CAP_ID_EXP)
        .map(|(offset, _)| u16::from(offset));
    let config = function.config();
    let identity = (
        config.read16(0x2c)?,
        config.read16(0x2e)?,
        config.read8(0x08)?,
    );
    let ltr = match express {
        Some(cap) if config.read16(cap + 2)? & EXP_FLAGS_VERS > 1 => {
            config.read16(cap + EXP_DEVCTL2)? & EXP_DEVCTL2_LTR_EN != 0
        }
        _ => false,
    };
    function.enable_polled_decode()?;
    Ok((identity.0, identity.1, identity.2, Host { ltr }))
}

/// Bus Master on for the bound requester, with MSI, MSI-X and INTx still
/// off: the bring-up polls, nothing would service an MSI, and the chip is
/// powered off again when it returns.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
fn rtw89_master<C: ConfigSpace>(function: &mut Function<C>) -> Result<(), Error> {
    function.enable_polled()?;
    Ok(())
}

/// The device effects of an RTL8852CE attach, which [`rtw89_attach`] puts
/// in order: the mount's, over its cold-prepared requester, or the host
/// check's (`--wifi-check`), which parks the function itself and gives it
/// the passthrough domain.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub trait Rtw89Device {
    type Io: AxIo;
    /// The register window over BAR2: memory decode on, Bus Master clear
    /// until [`Self::master`].
    fn io(&mut self) -> &mut Self::Io;
    /// What the bring-up needs of the PCIe host: the function's DEVCTL2
    /// `LTR_EN`, read while it was prepared.
    fn host(&self) -> Host;
    /// `PreparingRequester::acknowledge_quiescence`, then
    /// `QuiescenceReceipt::finalize`: the domain the original root binds for
    /// this requester.
    ///
    /// # Safety
    /// `acknowledge_quiescence`'s contract holds for this requester.
    unsafe fn finalize(&mut self) -> Result<Arc<dyn DmaDomain>, Error>;
    /// Bus Master on, with MSI, MSI-X and INTx left off.
    fn master(&mut self) -> Result<(), Error>;
}

/// One RTL8852CE through its attach: its requester as preparation hands it
/// on, the register window over its BAR2 until a station takes it, and the
/// host input [`rtw89_decode`] read. Every outcome keeps it whole.
struct Rtw89Native {
    claim: Rtw89Claim,
    io: Rtw89Window<NativeAxIo>,
    host: Host,
}

enum Rtw89Claim {
    Preparing(PreparingRequester),
    /// Finalization refused; its failure keeps the original owners.
    Refused {
        _kept: PreparationFailure,
    },
    Bound {
        function: Function<OwnedConfig>,
        _attachment: Attachment,
    },
    /// Only while finalization runs.
    Finalizing,
}

impl Rtw89Device for Rtw89Native {
    type Io = Rtw89Window<NativeAxIo>;
    fn io(&mut self) -> &mut Rtw89Window<NativeAxIo> {
        &mut self.io
    }
    fn host(&self) -> Host {
        self.host
    }
    unsafe fn finalize(&mut self) -> Result<Arc<dyn DmaDomain>, Error> {
        let preparing = match core::mem::replace(&mut self.claim, Rtw89Claim::Finalizing) {
            Rtw89Claim::Preparing(preparing) => preparing,
            other => {
                self.claim = other;
                return Err(Error::Native(ServiceError::Refused(
                    "the RTL8852CE requester has left preparation",
                )));
            }
        };
        // SAFETY: the caller's `acknowledge_quiescence` contract.
        match unsafe { preparing.acknowledge_quiescence() }.finalize() {
            Ok(bound) => {
                let domain = bound.attachment.domain();
                self.claim = Rtw89Claim::Bound {
                    function: bound.requester.into_function(),
                    _attachment: bound.attachment,
                };
                Ok(domain)
            }
            Err(failure) => {
                let error = Error::Preparation(failure.error);
                self.claim = Rtw89Claim::Refused { _kept: failure };
                Err(error)
            }
        }
    }
    fn master(&mut self) -> Result<(), Error> {
        match &mut self.claim {
            Rtw89Claim::Bound { function, .. } => rtw89_master(function),
            _ => Err(Error::Native(ServiceError::Refused(
                "the RTL8852CE requester is not bound",
            ))),
        }
    }
}

/// Bring the RTL8852CE `observed` describes up to running firmware through
/// `device`, in this order:
/// 1. stage `firmware`: a missing or unusable image fails here, before any
///    register access, and so does a file whose PHY table elements are
///    unreadable or lack a table the bring-up applies (`"phy tables"`,
///    [`check_tables`]);
/// 2. [`quiesce`] the chip through BAR2, powering off a MAC left on;
/// 3. acknowledge its quiescence and bind its own domain;
/// 4. set Bus Master;
/// 5. [`bring_up`] on that domain, with the file, whose PHY and TX power
///    tables it reads again (a file without TX power tables fails there, at
///    `"firmware elements"`, after the efuse its RFE type comes from).
///
/// Returns the report, the rings DMA ran on, and whether the MAC was on;
/// a failure is returned with whether the MAC was on as well, since a MAC
/// left on was powered off before any failure past step 2.
///
/// # Safety
/// `device.io()` is the exclusive uncached BAR2 window of the original PCI
/// requester `device.finalize` finalizes, which the mount parked with Bus
/// Master clear and its outstanding requests drained, and whose seal has
/// held Bus Master clear since; the mount's cold grant excludes earlier
/// firmware, IRQ and work users and competing writers. `device.finalize`
/// is `QuiescenceReceipt::finalize` of that requester, and `device` keeps
/// BAR2 and every owner of the receipt through each outcome. `pages` is
/// coherent write-back RAM, and nothing else drives the function.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub unsafe fn rtw89_attach<D: Rtw89Device + ?Sized>(
    device: &mut D,
    observed: realtek_wifi::identity::Observed,
    firmware: &dyn crate::firmware::Provider,
    pages: &dyn PageSource,
) -> Result<(Running, Rings, bool), (Error, bool)> {
    // SAFETY: this function's contract is `rtw89_attach_with`'s; and
    // `bring_up` runs at its step 5, where `rtw89_attach_with` promises
    // `bring_up`'s contract for `io`, `pages` and `domain`.
    let attached = unsafe {
        rtw89_attach_with(
            device,
            observed,
            firmware,
            pages,
            |io, pages, domain, cut, firmware, host| {
                bring_up(io, pages, domain, cut, firmware, host).map_err(Error::Rtw89Wifi)
            },
        )
    };
    attached.map(|((running, rings), was_on)| (running, rings, was_on))
}

/// [`rtw89_attach`] with `run` at step 5 in place of [`bring_up`]: `run` is
/// called once, after Bus Master is set, with the register window, `pages`,
/// the domain just bound, the chip cut, the staged firmware file and the
/// host input, and [`bring_up`]'s contract holds for the window, the pages
/// and the domain while it runs. The host check's station check runs
/// [`realtek_wifi::ax::attach`] and its keeper there. Returns what `run`
/// returned and whether the MAC was on, as [`rtw89_attach`] does.
///
/// # Safety
/// As for [`rtw89_attach`].
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
pub unsafe fn rtw89_attach_with<D: Rtw89Device + ?Sized, T>(
    device: &mut D,
    observed: realtek_wifi::identity::Observed,
    firmware: &dyn crate::firmware::Provider,
    pages: &dyn PageSource,
    run: impl FnOnce(
        &mut D::Io,
        &dyn PageSource,
        Arc<dyn DmaDomain>,
        u8,
        FirmwareFile<'_>,
        Host,
    ) -> Result<T, Error>,
) -> Result<(T, bool), (Error, bool)> {
    use realtek_wifi::firmware::Layout;
    let fail = |step, error| (Error::Rtw89Wifi(BringUpError::new(step, error)), false);
    let (profile, staged) =
        rtw89_stage(observed, firmware).map_err(|error| (Error::Rtw89Wifi(error), false))?;
    let Layout::Rtw89(parsed) = &staged.layout else {
        return Err(fail(
            "firmware",
            AxError::FirmwareFile("rtw89/rtw8852c_fw-2.bin is not an rtw89 image"),
        ));
    };
    // The PHY tables the radio steps apply are the file's own elements
    // (`rtw89_build_phy_tbl_from_elm`, fw.c:1099); a file without them is
    // refused here, before any register access.
    let tables = phy_tables(staged.image.bytes(), 0).map_err(|_| {
        fail(
            "phy tables",
            AxError::FirmwareFile("rtw89/rtw8852c_fw-2.bin elements are unreadable"),
        )
    })?;
    check_tables(&tables).map_err(|error| fail("phy tables", error))?;
    let was_on = quiesce(device.io()).map_err(|error| fail("quiesce", error))?;
    let file = staged.image.bytes();
    // SAFETY: this function's contract, with the chip just quiesced.
    match unsafe { rtw89_take_over(device, profile.cut(), &parsed.image, file, pages, run) } {
        Ok(ran) => Ok((ran, was_on)),
        Err(error) => Err((error, was_on)),
    }
}

/// Steps 3 to 5 of [`rtw89_attach_with`], on a chip [`quiesce`] just
/// stopped: `run` is step 5.
///
/// # Safety
/// As for [`rtw89_attach`], and `quiesce` returned `Ok` on `device.io()`
/// just before.
#[expect(
    clippy::result_large_err,
    reason = "The shared error preserves exact source and cleanup causes without allocating on propagation."
)]
unsafe fn rtw89_take_over<D: Rtw89Device + ?Sized, T>(
    device: &mut D,
    cut: u8,
    image: &realtek_wifi::firmware::AxImage<'_>,
    file: &[u8],
    pages: &dyn PageSource,
    run: impl FnOnce(
        &mut D::Io,
        &dyn PageSource,
        Arc<dyn DmaDomain>,
        u8,
        FirmwareFile<'_>,
        Host,
    ) -> Result<T, Error>,
) -> Result<T, Error> {
    // SAFETY: `device.finalize()` acknowledges the quiescence
    // (`PreparingRequester::acknowledge_quiescence`, inside
    // `Rtw89Native::finalize`), then finalizes the receipt; its contract is
    // the acknowledgement's, point by point:
    // - Engine stop and submission exclusion, with no restart: Bus Master
    //   has been clear since the mount parked the function, so no engine of
    //   the chip reached memory. `quiesce` just read the MAC power state
    //   (R_AX_IC_PWR_STATE[9:8]) and returned only for two states:
    //   `MAC_AX_MAC_OFF`, in which the MAC domain (WCPU, DMAC and CMAC) is
    //   unpowered; or `MAC_AX_MAC_ON`, after it set B_AX_STOP_WPDMA, set
    //   the AXI master stop and cleared the TX/RX HCI DMA enables
    //   (`rtw89_pci_ctrl_dma_all(false)`), then ran `rtw8852c_pwr_off_func`
    //   (its XTAL SI power-down commands, the BB reset and pad clears,
    //   B_AX_APFM_OFFMAC set and polled until it cleared, then the PCIe
    //   low-power option and B_AX_APFM_SWLPS) and wrote the coex
    //   scoreboard. Either way the PCIe side has issued nothing since the
    //   park. LPS, where the firmware is alive, and the undefined state were
    //   refused before this. No Stela queue or ring exists yet, and only
    //   `run` below (`bring_up`, or the station's start) powers the MAC on
    //   again, after the binding.
    // - Firmware, IRQ delivery and worker users retired: the mount's cold
    //   grant excludes earlier firmware, IRQ and work users; MSI, MSI-X and
    //   INTx were turned off before BAR2 was read, no handler exists, and
    //   the probe runs nothing else on this function.
    // - Bypass and peer traffic: with Bus Master clear the function issues
    //   no request, peer or otherwise; finalization rechecks the stopped
    //   state, Enable No Snoop and ATS Enable among it, after the original
    //   root's drain.
    // - BARs and old backing kept: `device` keeps BAR2 and the receipt's
    //   owners through finalization and every failure. The chip had no
    //   Stela DMA backing before this point.
    let domain = unsafe { device.finalize() }?;
    device.master()?;
    // The DEVCTL2 LTR_EN read while the function was prepared.
    let host = device.host();
    let firmware = FirmwareFile { image, file };
    // `run` is called with `bring_up`'s contract holding, as
    // `rtw89_attach_with` promises it:
    // - `device.io()` is the exclusive register window of exactly the
    //   requester whose own domain `finalize` just bound: the receipt
    //   finalized this requester's snooped coherent domain through its
    //   original root, after that root's drain.
    // - `pages` is coherent write-back RAM the bound domain maps, and
    //   finalization refused the function unless Enable No Snoop and ATS
    //   Enable read clear; nothing here sets either (`master` sets only
    //   Bus Master, memory decode and INTx Disable).
    // - One worker: the probe drives this function alone, with no
    //   interrupt handler, reset or other engine reaching it.
    // `host` and `firmware` are no part of that contract: one decides
    // whether the chip's own LTR registers are programmed, the other what
    // is downloaded and what the BB, RF and TX power registers are set to.
    run(device.io(), pages, domain, cut, firmware, host)
}

/// The RTL8852C profile of `observed`, and its firmware staged from
/// `firmware`, before any register write.
fn rtw89_stage(
    observed: realtek_wifi::identity::Observed,
    firmware: &dyn crate::firmware::Provider,
) -> Result<
    (
        realtek_wifi::identity::Profile,
        realtek_wifi::identity::Staged<'_>,
    ),
    BringUpError,
> {
    use realtek_wifi::identity::{Chip, IdentityError, Profile};
    let fail = BringUpError::new;
    let profile = match Profile::select(observed) {
        Ok(profile) if profile.chip() == Chip::Rtl8852C => profile,
        Err(IdentityError::FailedRead) => {
            return Err(fail("identity", AxError::AllOnes { register: 0xf0 }));
        }
        Ok(_) | Err(IdentityError::UnsupportedPci | IdentityError::TestChip) => {
            return Err(fail(
                "identity",
                AxError::Identity(
                    "its PCI vendor and device IDs are not the RTL8852CE's 10ec:c852",
                ),
            ));
        }
    };
    let staged = profile
        .stage(firmware)
        .map_err(|error| fail("firmware", AxError::FirmwareFile(staging(&error))))?;
    Ok((profile, staged))
}

/// Why `rtw89/rtw8852c_fw-2.bin` could not be staged, in words.
fn staging(error: &realtek_wifi::identity::StageError) -> &'static str {
    use crate::firmware::ErrorKind;
    use realtek_wifi::{firmware::ParseError, identity::StageError};
    match error {
        StageError::Resource(error) => match error.kind {
            ErrorKind::Missing => "rtw89/rtw8852c_fw-2.bin is not on the USB stick",
            ErrorKind::WrongTarget => {
                "rtw89/rtw8852c_fw-2.bin is on the USB stick only for another adapter, neither \
                 this one nor the RTL8852CE chip binding"
            }
            ErrorKind::Truncated { .. } => {
                "rtw89/rtw8852c_fw-2.bin on the USB stick is shorter than an rtw89 header"
            }
            ErrorKind::LengthMismatch { .. } | ErrorKind::DigestMismatch { .. } => {
                "rtw89/rtw8852c_fw-2.bin on the USB stick does not match its pinned length and \
                 SHA-256"
            }
            ErrorKind::Duplicate | ErrorKind::Conflict => {
                "rtw89/rtw8852c_fw-2.bin is on the USB stick twice or with conflicting manifests"
            }
            ErrorKind::InvalidName
            | ErrorKind::InvalidTarget(_)
            | ErrorKind::InvalidProvenance(_)
            | ErrorKind::InvalidRequirement => "the request for rtw89/rtw8852c_fw-2.bin is invalid",
        },
        StageError::Format(error) => match error {
            ParseError::NoCompatibleFirmware { .. } => {
                "rtw89/rtw8852c_fw-2.bin has no image for this chip cut"
            }
            ParseError::UnsupportedHeader(_) => {
                "rtw89/rtw8852c_fw-2.bin has a firmware header version other than 0"
            }
            ParseError::UnsupportedFormattedSecurity(_) => {
                "rtw89/rtw8852c_fw-2.bin has a security section format not supported here"
            }
            ParseError::Truncated { .. } => "rtw89/rtw8852c_fw-2.bin is truncated",
            ParseError::ResourceLimit
            | ParseError::Length
            | ParseError::AddressOverflow
            | ParseError::Signature
            | ParseError::EmptyContainer
            | ParseError::TooManySections(_)
            | ParseError::DynamicHeader => "rtw89/rtw8852c_fw-2.bin is malformed",
        },
    }
}

/// Attach an Intel Wi-Fi function: BAR0 holds its CSRs.
///
/// # Safety
/// As for [`tg3`]; `inputs.bios` reads this function's own ACPI companion.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
#[cfg(feature = "native-acpi")]
pub(super) unsafe fn intel_wifi<B: wifi::intel::radio::bios::service::BiosIo>(
    services: &dyn NativeServices,
    address: Address,
    completion: Option<crate::bus::irq::MsiMessage>,
    inputs: wifi::intel::link::Inputs<B>,
) -> Result<Located<wifi::intel::link::Station<wifi::intel::boot::NativeBootIo, B>>, Failure> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    use wifi::intel::attach::{AttachError, Pci, attach};
    let Claimed {
        mut function,
        domain,
        bars,
    } = claim(services, address)?;
    let registers = match map(services, address, &bars, 0) {
        Ok(registers) => registers,
        Err(error) => return Err(keep_error(Error::Native(error), (function, domain))),
    };
    let window = match registers.address(0, 16384) {
        Ok(window) => window,
        Err(error) => {
            return Err(keep_error(
                Error::Native(ServiceError::Mapping(error)),
                (function, domain, registers),
            ));
        }
    };
    let configured = (|| -> Result<_, Error> {
        let vendor = function.vendor;
        let device = function.device;
        let link_speed = crate::bus::pci::link_speed(&function)?;
        let config = function.config();
        let pci = Pci {
            vendor,
            device,
            subsystem_vendor: config.read16(0x2c)?,
            subsystem_device: config.read16(0x2e)?,
            revision: config.read8(0x08)?,
            link_speed,
            vector: false,
        };
        let interrupt = function.interrupts()?.msix;
        function.enable_polled()?;
        let vector = match (completion, interrupt) {
            (Some(message), Some(msix)) if msix.table_bar == 0 => {
                let table = registers
                    .address(msix.table_offset as usize, 16)
                    .map_err(|error| Error::Native(ServiceError::Mapping(error)))?;
                // SAFETY: this function's owned uncached MSI-X table stays kept.
                let table = unsafe { crate::bus::mmio::Mmio::new(table.as_ptr() as u64, 16) };
                let vector = IntelVector {
                    msix,
                    table,
                    message,
                };
                vector.enable(&mut function)?;
                Some(vector)
            }
            _ => None,
        };
        Ok((
            Pci {
                vector: vector.is_some(),
                ..pci
            },
            vector,
        ))
    })();
    let (pci, vector) = match configured {
        Ok(configured) => configured,
        Err(error) => return Err(keep_error(error, (function, domain, registers))),
    };
    let owner: Rc<dyn wifi::intel::boot::FunctionOwner> = Rc::new(IntelOwner {
        function: RefCell::new(function),
        _registers: registers,
        vector,
        minimum: minimum.clone(),
    });
    let kept = |owner: &Rc<dyn wifi::intel::boot::FunctionOwner>| {
        Some(Box::new(owner.clone()) as Box<dyn Any>)
    };
    // SAFETY: the mount claimed the stopped function and mapped its BAR0
    // uncached; `owner` keeps both, and its interrupts are off.
    let io = unsafe {
        wifi::intel::boot::NativeBootIo::from_window(window.cast(), owner.clone(), minimum.clone())
    }
    .map_err(|error| (Error::IntelWifi(AttachError::Boot(error)), kept(&owner)))?;
    // SAFETY: the mount's domain isolates this requester, and the caller's
    // contract covers `inputs`.
    match unsafe { attach(io, pci, domain, inputs) } {
        Ok(link) => Ok(Located {
            location: alloc::format!("{address}"),
            link,
        }),
        Err(error) => Err((Error::IntelWifi(error), kept(&owner))),
    }
}

/// The MSI-X vector an Intel radio's completions arrive on.
#[cfg(feature = "native-acpi")]
struct IntelVector {
    msix: crate::bus::pci::MsiX,
    table: crate::bus::mmio::Mmio,
    message: crate::bus::irq::MsiMessage,
}

#[cfg(feature = "native-acpi")]
impl IntelVector {
    fn enable(&self, function: &mut Function<OwnedConfig>) -> Result<(), crate::block::BlockError> {
        function.enable_msix(self.msix, || {
            self.table.write32(0, self.message.address as u32);
            self.table.write32(4, (self.message.address >> 32) as u32);
            self.table.write32(8, self.message.data);
            self.table.write32(12, 0);
            Ok(())
        })
    }
}

/// An Intel radio's function, with everything that outlives its users.
#[cfg(feature = "native-acpi")]
struct IntelOwner {
    function: RefCell<Function<OwnedConfig>>,
    _registers: Mapping,
    vector: Option<IntelVector>,
    minimum: Rc<dyn crate::bus::pci::power::Timer>,
}

#[cfg(feature = "native-acpi")]
impl wifi::intel::boot::FunctionOwner for IntelOwner {
    /// `pci_reset_function`, of its methods the one Intel radios have, with
    /// the vector back as `pci_restore_state` puts it.
    fn reset(&self) -> Result<bool, crate::block::BlockError> {
        let mut function = self.function.borrow_mut();
        let reset = function.function_level_reset(self.minimum.as_ref())?;
        if reset && let Some(vector) = &self.vector {
            vector.enable(&mut function)?;
        }
        Ok(reset)
    }
}

/// The ACPI companion of the function at `address`, as Linux's
/// `acpi_pci_find_companion` finds it: from the root bridge whose `_SEG` and
/// `_BBN` name its root bus, the child whose `_ADR` names each bridge on the
/// way down, then the function. `bridges` lists each PCI bridge with its
/// secondary bus.
#[cfg(feature = "native-acpi")]
pub(super) fn companion<'a>(
    session: &'a crate::platform::acpi::Session,
    address: Address,
    bridges: &[Bridge],
) -> Option<crate::platform::acpi::Handle<'a>> {
    use crate::platform::acpi::Handle;
    let parent = |handle: Handle<'a>| -> Option<String> {
        let path = handle.path().ok()?;
        path.rsplit_once('.')
            .map(|(parent, _)| String::from(parent))
    };
    let mut chain = alloc::vec![(address, false)];
    let mut bus = address.bus;
    while let Some(bridge) = upstream(bridges, address.segment, bus) {
        chain.push((bridge.address, true));
        bus = bridge.address.bus;
    }
    let devices = session.all_devices().ok()?;
    let (mut current, ..) = roots(session)
        .into_iter()
        .find(|&(_, segment, root)| segment == address.segment && root == bus)?;
    for (address, bridge) in chain.into_iter().rev() {
        let path = current.path().ok()?;
        let adr = (u64::from(address.device) << 16) | u64::from(address.function);
        // acpi_find_child_device and find_child_checks: an enabled device
        // without _HID wins; one without _STA or with a _HID only scores
        // lower; a bridge's companion needs children.
        let mut best: Option<(u8, Handle<'a>)> = None;
        for &device in &devices {
            if parent(device).as_deref() != Some(path.as_str())
                || integer(device, "_ADR") != Some(adr)
            {
                continue;
            }
            if bridge {
                let own = device.path().ok()?;
                if !devices
                    .iter()
                    .any(|child| parent(*child).as_deref() == Some(own.as_str()))
                {
                    continue;
                }
            }
            let score = if device.child("_STA").is_err() {
                1
            } else if integer(device, "_STA").is_none_or(|status| status & 2 == 0) {
                continue;
            } else if device.child("_HID").is_ok() {
                1
            } else {
                3
            };
            if best.is_none_or(|(kept, _)| score > kept) {
                best = Some((score, device));
            }
            if score == 3 {
                break;
            }
        }
        current = best?.1;
    }
    Some(current)
}

/// The VMD parent's BAR registers as read, its memory BARs as the PCI core
/// sized them, and its VMCAP and VMCONFIG, which a refusal of the host's own
/// resources names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmdWords {
    pub registers: [u32; 6],
    pub sized: [Option<(u64, u64)>; 3],
    pub vmcap: u16,
    pub vmconfig: u16,
}

impl VmdWords {
    fn read(
        config: &impl ConfigSpace,
        bars: &[Option<Bar>; 6],
    ) -> Result<Self, crate::bus::pci::ConfigError> {
        let mut registers = [0; 6];
        for (index, register) in registers.iter_mut().enumerate() {
            *register = config.read32(0x10 + index as u16 * 4)?;
        }
        let sized = [0, 2, 4].map(|index| match bars[index] {
            Some(Bar::Memory { address, size, .. }) => Some((address, size)),
            _ => None,
        });
        Ok(Self {
            registers,
            sized,
            vmcap: config.read16(0x40)?,
            vmconfig: config.read16(0x44)?,
        })
    }
}

impl core::fmt::Display for VmdWords {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BAR registers")?;
        for register in self.registers {
            write!(f, " {register:08x}")?;
        }
        f.write_str(", sized")?;
        for (index, sized) in [0, 2, 4].into_iter().zip(self.sized) {
            match sized {
                Some((address, size)) => write!(f, " BAR{index} {address:#x}+{size:#x}")?,
                None => write!(f, " BAR{index} none")?,
            }
        }
        write!(
            f,
            ", VMCAP {:04x} VMCONFIG {:04x}",
            self.vmcap, self.vmconfig
        )
    }
}

/// An Intel VMD host's NVMe controllers, each attached or with the reason it
/// is not, by location, the devices behind it no driver here takes, and the
/// hierarchy owner that hands back the parent's owners when every attached
/// controller retires.
pub struct Vmd {
    pub nvme: Vec<(String, Result<nvme::Attached, crate::block::BlockError>)>,
    pub others: Vec<vmd::Child>,
    pub owner: Box<dyn Any>,
}

/// Attach every NVMe controller behind an Intel VMD host: BAR0 holds the
/// children's configuration space, BAR2 and BAR4 their memory windows.
///
/// # Safety
/// As for [`tg3`]; every device behind the host is stopped as well.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn vmd(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
    platform: &crate::firmware::smbios::SystemIdentity<'_>,
) -> Result<Vmd, Failure> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    let refused = |error: ServiceError| (Error::Native(error), None);
    let failed = |error: vmd::Error, owner: Box<dyn Any>| (Error::Vmd(error), Some(owner));
    let mut preparing = services.prepare_requester(address).map_err(refused)?;
    let function = preparing.function_mut();
    let profile = match vmd::Profile::identify(function.vendor, function.device) {
        Ok(profile) => profile,
        Err(error) => return Err(keep_error(Error::Vmd(error), preparing)),
    };
    let bars = match preparing.function_mut().bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, preparing)),
    };
    let words = match VmdWords::read(preparing.function_mut().config(), &bars) {
        Ok(words) => words,
        Err(error) => return Err(keep_error(error, preparing)),
    };
    // A refusal of the host's own BARs or bus range names what it read.
    let host_error = |error: vmd::Error| match error {
        vmd::Error::InvalidResource => Error::VmdResource(error, words),
        error => Error::Vmd(error),
    };
    // SAFETY: VMD has no engine of its own: every request it issues is a
    // child's, forwarded upstream under its requester ID. Its Bus Master bit
    // has been clear since the mount parked it, the preparation's seal keeps
    // it so, and finalization releases the seal without setting the bit.
    // Only the hierarchy owner sets it again, after discovery stopped every
    // child firmware left mastering (refusing one that does not stop),
    // preparation cleared every child's Bus Master and the NVMe driver
    // disabled its controller. The cold grant excludes prior
    // firmware, IRQ and work users; no Stela producer exists yet. The BARs
    // were sized with decode as the mount left it, and finalization rechecks
    // the stopped state after the original root's drain.
    let bound = match unsafe { preparing.acknowledge_quiescence() }.finalize() {
        Ok(bound) => bound,
        Err(failure) => {
            return Err((Error::Preparation(failure.error), Some(Box::new(failure))));
        }
    };
    let domain = bound.attachment.domain();
    let (requester, attachment) = (bound.requester, bound.attachment);
    let reserve = |index: usize| match bars[index] {
        Some(bar @ Bar::Memory { .. }) => services.bar_resource(address, bar),
        _ => Err(ServiceError::Refused("missing memory BAR")),
    };
    // A failure here keeps the stopped requester and its attachment, as
    // every later failure keeps them with the host.
    let reserved = (|| {
        let bars = [reserve(0)?, reserve(2)?, reserve(4)?];
        let authority = services.authority()?;
        let map = |resource: &crate::bus::mmio::owned::Resource, window: core::ops::Range<u64>| {
            authority
                .map(
                    resource.clone(),
                    window.start as usize,
                    (window.end - window.start) as usize,
                    CacheAttribute::Uncached,
                    Protection::ReadWrite,
                )
                .map_err(ServiceError::Mapping)
        };
        let configuration = map(&bars[0], 0..bars[0].physical_span().bytes())?;
        let shadow = profile
            .shadow_window()
            .map(|window| map(&bars[2], window))
            .transpose()?;
        Ok::<_, ServiceError>((bars, authority, configuration, shadow))
    })();
    let (bars, authority, configuration, shadow) = match reserved {
        Ok(reserved) => reserved,
        Err(error) => return Err(keep_error(Error::Native(error), (requester, attachment))),
    };
    let resources = vmd::NativeResources {
        requester,
        bars,
        cfgbar: configuration,
        shadow,
        msix: None,
    };
    // SAFETY: the mount reserved and mapped these BARs for this stopped host,
    // and no other owner reaches the hierarchy behind it.
    let registers = match unsafe { vmd::NativeRegisters::claim(resources) } {
        Ok(registers) => registers,
        Err((error, resources)) => {
            return Err(keep_error(host_error(error), (resources, attachment)));
        }
    };
    let mut host = match vmd::Host::initialize(registers) {
        Ok(host) => host,
        Err((error, registers)) => {
            return Err(keep_error(host_error(error), (registers, attachment)));
        }
    };
    let mut others = match host.scan() {
        Ok(children) => children,
        Err(error) => return Err(failed(error, Box::new((host, attachment)))),
    };
    let location = |child: &vmd::Child| {
        alloc::format!(
            "{address} VMD {:02x}:{:02x}.{}",
            child.address.bus,
            child.address.device,
            child.address.function
        )
    };
    // Every NVMe controller below the host, each with its own firmware BAR0
    // inside the host's windows, as Linux's VMD driver enumerates them; one
    // whose BAR is refused stays a stopped function with its own cause.
    let mut controllers = Vec::new();
    let mut unclaimed = Vec::new();
    let mut index = 0;
    while index < others.len() {
        if others[index].class != [1, 8, 2] {
            index += 1;
            continue;
        }
        let child = others.remove(index);
        let label = location(&child);
        // SAFETY: `bytes` is the child's firmware-assigned BAR0, sized with
        // its decode off, and the stopped hierarchy has no other owner.
        let bar = host
            .memory_bar_bytes(child.address)
            .and_then(|bytes| unsafe {
                vmd::endpoint::FirmwareBar::claim(&mut host, child.address, bytes)
            });
        match bar {
            Ok(bar) => controllers.push(crate::storage::nvme::vmd::Controller {
                bar,
                label,
                quirks: nvme::Quirks::for_device(child.vendor, child.device)
                    | nvme::Quirks::for_platform(child.vendor, child.device, platform),
            }),
            Err(error) => unclaimed.push((label, error)),
        }
    }
    let unclaimed = unclaimed
        .into_iter()
        .map(|(label, error)| (label, Err(crate::storage::nvme::vmd::block(error))));
    if controllers.is_empty() {
        // No controller's BAR could be claimed: each is reported by its
        // location with its own cause, and the host keeps its owners.
        return Ok(Vmd {
            nvme: unclaimed.collect(),
            others,
            owner: Box::new((host, attachment)),
        });
    }
    // SAFETY: the host's own attached domain covers its requester, under
    // which every child's request reaches the root; the mount's permission
    // issued these mappings, and the hierarchy is stopped.
    match unsafe {
        crate::storage::nvme::vmd::attach(
            host,
            controllers,
            domain,
            authority,
            services.pages(),
            clock,
            minimum.clone(),
        )
    } {
        Ok((attached, hierarchy)) => Ok(Vmd {
            nvme: attached.into_iter().chain(unclaimed).collect(),
            others,
            owner: Box::new((hierarchy, attachment)),
        }),
        Err((error, hierarchy)) => Err((
            Error::Device(error),
            Some(Box::new((hierarchy, attachment))),
        )),
    }
}

/// An Intel PCIe Bluetooth transport over its owned BAR0, whose MSI-X table
/// entry 0 delivers its interrupts.
pub type IntelBluetooth =
    intel_pcie::native::lifetime::OwnedTransport<MappedBar, intel_pcie::native::MappedRegisters>;

/// A Broadcom BCM4377-family transport over its owned BAR0 and BAR2, whose
/// MSI delivers its interrupts.
pub type Bcm4377 = bcm4377::Transport<bcm4377::native::NativePlatform>;

/// An attached PCIe Bluetooth controller and its one firmware initialization
/// attempt. A kept success is not radio or guest readiness.
pub struct PcieHci {
    pub location: String,
    pub controller: PcieController,
}

#[allow(
    clippy::large_enum_variant,
    reason = "one controller per attached function, kept for the boot"
)]
pub enum PcieController {
    Intel {
        transport: IntelBluetooth,
        initialization: Result<intel_pcie::firmware::Report, intel_pcie::firmware::Error>,
    },
    Broadcom {
        transport: Bcm4377,
        initialization: Result<bcm4377::Report, bcm4377::Error>,
    },
}

/// The root buses of `segment`, as the ACPI host bridges' `_SEG` and `_BBN`
/// declare them.
#[cfg(feature = "native-acpi")]
pub(super) fn root_buses(
    session: &'static crate::platform::acpi::Session,
    segment: u16,
) -> Vec<crate::bus::pci::native_aspm::RootBus> {
    use crate::bus::pci::native_aspm::RootBus;
    roots(session)
        .into_iter()
        .filter(|&(_, root_segment, _)| root_segment == segment)
        .map(|(_, segment, bus)| RootBus { segment, bus })
        .collect()
}

/// Each ACPI PCI host bridge with its `_SEG` and `_BBN`, zero when absent.
#[cfg(feature = "native-acpi")]
pub(super) fn roots(
    session: &crate::platform::acpi::Session,
) -> Vec<(crate::platform::acpi::Handle<'_>, u16, u8)> {
    let mut roots = session.devices("PNP0A08").unwrap_or_default();
    roots.extend(session.devices("PNP0A03").unwrap_or_default());
    roots
        .into_iter()
        .filter_map(|root| {
            let segment = u16::try_from(integer(root, "_SEG").unwrap_or(0)).ok()?;
            let bus = u8::try_from(integer(root, "_BBN").unwrap_or(0)).ok()?;
            Some((root, segment, bus))
        })
        .collect()
}

/// The integer `name` evaluates to on `handle`, when it has one.
#[cfg(feature = "native-acpi")]
pub(super) fn integer(handle: crate::platform::acpi::Handle<'_>, name: &str) -> Option<u64> {
    use crate::platform::acpi::Value;
    handle.child(name).ok()?;
    match handle.evaluate(Some(name), &[]).ok()? {
        Some(Value::Integer(value)) => Some(value),
        _ => None,
    }
}

/// Attach a Broadcom PCIe Bluetooth function, as `bcm4377_probe` does:
/// BAR0 and BAR2 hold its registers, `topology` its link's bridges and
/// `board` the board its firmware is chosen for.
///
/// # Safety
/// As for [`tg3`]; `topology` holds the mount's bridges of the function's
/// segment and its root buses, and no other owner sets their link policy.
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn bcm4377(
    services: &dyn NativeServices,
    address: Address,
    topology: crate::bus::pci::native_aspm::Topology<OwnedConfig>,
    board: bcm4377::Board,
    clock: Clock,
) -> Result<Bcm4377, Failure> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    use bcm4377::native::{
        Error as NativeError, Inputs, MappedRegisters, NativeClock, NativePlatform, cold,
    };
    let refused = |error: ServiceError| (Error::Native(error), None);
    let failed =
        |error: NativeError, kept: Box<dyn Any>| (Error::Bcm4377(error.into()), Some(kept));
    // SAFETY: the handoff's clock is the calibrated invariant TSC.
    let clock =
        unsafe { NativeClock::new(clock) }.map_err(|error| (Error::Bcm4377(error.into()), None))?;
    let interrupts = services.interrupts().map_err(refused)?;
    let authority = services.authority().map_err(refused)?;
    let mut requester = services.prepare_requester(address).map_err(refused)?;
    // Restore D0 before BAR sizing under the original configuration/root owner.
    if let Err(error) = requester.function_mut().power_up(minimum.as_ref()) {
        return Err(failed(
            NativeError::Power(error),
            Box::new((requester, topology)),
        ));
    }
    let bars = match requester.function_mut().bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, (requester, topology))),
    };
    let bar0 = match map(services, address, &bars, 0) {
        Ok(mapping) => mapping,
        Err(error) => return Err((Error::Native(error), Some(Box::new((requester, topology))))),
    };
    let bar2 = match map(services, address, &bars, 2) {
        Ok(mapping) => mapping,
        Err(error) => {
            return Err((
                Error::Native(error),
                Some(Box::new((requester, topology, bar0))),
            ));
        }
    };
    let spans = match (bar0.physical_span(), bar2.physical_span()) {
        (Ok(bar0), Ok(bar2)) => [bar0, bar2],
        (Err(error), _) | (_, Err(error)) => {
            return Err(failed(
                NativeError::Mapping(error),
                Box::new((requester, topology, bar0, bar2)),
            ));
        }
    };
    // SAFETY: the mount mapped exactly BAR0 and BAR2 uncached, once each.
    let registers = match unsafe { MappedRegisters::new(spans, [bar0, bar2]) } {
        Ok(registers) => registers,
        Err((error, mappings)) => {
            return Err(failed(error, Box::new((requester, topology, mappings))));
        }
    };
    let cold_inputs = cold::Inputs {
        requester,
        topology,
        registers,
        clock,
        minimum: minimum.clone(),
    };
    // SAFETY: original requester/BAR/root/backing are held, prior firmware,
    // IRQ/work, bypass and competing PCI writers excluded. No private DMA yet.
    let cold = unsafe { cold::Cold::new(cold_inputs) }
        .map_err(|(error, inputs)| failed(error, Box::new(inputs)))?;
    let bound = match cold.quiesce_and_bind() {
        Ok(bound) => bound,
        Err(failure) => return Err(failed(failure.error.clone(), Box::new(failure))),
    };
    let inputs = Inputs {
        function: bound.function,
        retained: Arc::new(authority),
        topology: bound.topology,
        registers: bound.registers,
        attachment: bound.attachment,
        pages: Box::new(services.pages()),
        board,
        // An x86 board's firmware node carries none of the device-tree
        // calibration or address properties Apple silicon boards do.
        properties: Vec::new(),
        clock: bound.clock,
        minimum: bound.minimum,
        interrupts,
    };
    // SAFETY: vendor FLR/D0/BAR restore, original-root drain and current-epoch
    // binding completed under the same owners. Constructor performs no reset;
    // only its subsequent transport preparation enables the new domain's BME.
    let platform = unsafe { NativePlatform::new(inputs) }
        .map_err(|(error, inputs)| failed(error, Box::new(inputs)))?;
    platform
        .into_transport()
        .map_err(|error| (Error::Bcm4377(error), None))
}

/// Attach an Intel PCIe Bluetooth function and start its ROM transport, as
/// `btintel_pcie_probe` does before downloading firmware. Its reset is the
/// function's own, so it needs no coordination with the Wi-Fi function of the
/// same module, as in Linux.
///
/// # Safety
/// As for [`tg3`].
#[allow(
    clippy::result_large_err,
    reason = "a failed attach hands back the owners that must outlive the device"
)]
pub(super) unsafe fn intel_bluetooth(
    services: &dyn NativeServices,
    address: Address,
    clock: Clock,
) -> Result<IntelBluetooth, Failure> {
    let minimum = services
        .minimum_delay()
        .map_err(|error| (Error::Native(error), None))?;
    use intel_pcie::native::{self as native, Inputs, NativePlatform, cold, lifetime};
    let refused = |error: ServiceError| (Error::Native(error), None);
    let failed =
        |error: intel_pcie::Error, kept: Box<dyn Any>| (Error::IntelBluetooth(error), Some(kept));
    let mut requester = services.prepare_requester(address).map_err(refused)?;
    // Power restoration precedes sizing/MMIO, with the original root/backing
    // still held and requester DMA gated by preparation.
    if let Err(error) = requester.function_mut().power_up(minimum.as_ref()) {
        return Err(failed(
            native::Error::Power(error).into(),
            Box::new(requester),
        ));
    }
    let bars = match requester.function_mut().bars() {
        Ok(bars) => bars,
        Err(error) => return Err(keep_error(error, requester)),
    };
    let interrupts = services.interrupts().map_err(refused)?;
    let authority = services.authority().map_err(refused)?;
    let Some(bar @ Bar::Memory { .. }) = bars[0] else {
        return Err(refused(ServiceError::Refused("missing memory BAR")));
    };
    let mapping = services.map_bar(address, bar).map_err(refused)?;
    let full = match mapping.physical_span() {
        Ok(span) => span,
        Err(error) => {
            return Err(failed(
                native::Error::Mapping(error).into(),
                Box::new((requester, mapping)),
            ));
        }
    };
    // SAFETY: same original complete UC BAR0. This table view is not used
    // until after cold reset, original-root drain and private attachment.
    let table = match unsafe { MappedBar::new(full, [Some(&mapping), None]) } {
        Ok(table) => table,
        Err(error) => {
            return Err(failed(
                native::Error::Msix(error).into(),
                Box::new((requester, mapping)),
            ));
        }
    };
    // SAFETY: original exclusively owned BAR0, with the inactive table view
    // kept locally. The cold owner preserves this mapping through every failure.
    let registers = match unsafe { native::MappedRegisters::new(full, mapping) } {
        Ok(registers) => registers,
        Err((error, mapping)) => {
            return Err(failed(error.into(), Box::new((requester, mapping, table))));
        }
    };
    let inputs = cold::Inputs {
        requester,
        registers,
        clock,
        minimum: minimum.clone(),
    };
    // SAFETY: the original function is powered D0; prior IRQ/work/firmware,
    // competing writers and bypass are excluded by the mount. Clock/backing
    // remain the original provider's. No private allocation or IRQ exists yet.
    let cold = match unsafe { cold::Cold::new(inputs) } {
        Ok(cold) => cold,
        Err((error, inputs)) => return Err(failed(error, Box::new((inputs, table)))),
    };
    let mut bound = match cold.quiesce_and_bind() {
        Ok(bound) => bound,
        Err(failure) => {
            let error = failure.error.clone();
            return Err(failed(error, Box::new((failure, table))));
        }
    };
    let mut function = bound.requester.into_function();
    let retention = match function.config().retain_epoch() {
        Ok(retention) => retention,
        Err(error) => {
            return Err(failed(
                native::Error::Mapping(error).into(),
                Box::new((function, bound.registers, bound.attachment)),
            ));
        }
    };
    match bound.attachment.matches_config(function.config()) {
        Ok(true) => {}
        Ok(false) => {
            return Err(failed(
                native::Error::Requirement("same original BT config allocation").into(),
                Box::new((function, bound.registers, bound.attachment, retention)),
            ));
        }
        Err(error) => {
            return Err(failed(
                native::Error::Dma {
                    operation: lifetime::DmaOperation::Drain,
                    source: error,
                }
                .into(),
                Box::new((function, bound.registers, bound.attachment, retention)),
            ));
        }
    }
    // Vendor disconnect/reset, original-root drain and current-epoch binding
    // are complete. BME now permits only the subsequently allocated new domain.
    if let Err(error) = function.enable_polled() {
        return Err(keep_error(
            error,
            (
                function,
                bound.registers,
                bound.attachment,
                retention,
                table,
            ),
        ));
    }
    let mut msix = [const { None }; 6];
    msix[0] = Some(table);
    let msi_route = match bound.attachment.irq_route() {
        Ok(route) => route,
        Err(error) => {
            return Err(failed(
                native::Error::Dma {
                    operation: lifetime::DmaOperation::Drain,
                    source: error,
                }
                .into(),
                Box::new((function, msix, bound.registers, bound.attachment, retention)),
            ));
        }
    };
    let inputs = Inputs {
        function,
        retained: Arc::new(authority),
        bars: msix,
        registers: bound.registers,
        clock,
        minimum: minimum.clone(),
        interrupts,
        domain: bound.attachment.domain(),
        msi_route,
    };
    // SAFETY: same original stopped function/root, acknowledged memory/BME,
    // coherent domain, routed IRQ provider and checked UC/MSI-X owners.
    let platform = match unsafe { NativePlatform::new(inputs) } {
        Ok(platform) => platform,
        Err((error, inputs)) => {
            return Err(failed(
                error.into(),
                Box::new((inputs, bound.attachment, retention)),
            ));
        }
    };
    // SAFETY: receipt finalized this exact requester's snooped coherent domain,
    // with all old backing held through its original completion; DMA is 64-bit.
    let allocator =
        unsafe { DomainAllocator::new(services.pages(), bound.attachment.domain(), u64::MAX) };
    let inputs = lifetime::Inputs {
        platform,
        allocator,
        attachment: bound.attachment,
        retention,
    };
    // SAFETY: these are the same original function, configuration seal, unique
    // attachment and allocator. The native owner retains them through teardown.
    let mut transport = unsafe { lifetime::OwnedTransport::new(inputs) }
        .map_err(|failure| failed(failure.error.clone(), Box::new(failure)))?;
    match transport.start() {
        Ok(()) => Ok(transport),
        Err(error) => Err(failed(error, Box::new(transport))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::services::tests::Refusing;

    fn address() -> Address {
        Address {
            segment: 0,
            bus: 3,
            device: 0,
            function: 0,
        }
    }

    #[test]
    fn missing_minimum_refuses_before_any_native_preparation() {
        let services = Refusing::default();
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        // SAFETY: all physical services refuse; no device capability exists.
        let error = unsafe { ehci(&services, address(), clock) };
        assert!(matches!(
            error,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert!(services.requests.borrow().is_empty());
        assert!(services.preparations.borrow().is_empty());
    }
    #[test]
    fn ehci_requests_original_preparation_without_a_stopped_or_bound_grant() {
        let services = Refusing::minimum_only();
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        // SAFETY: refusing services transfer no owner or hardware access.
        let result = unsafe { ehci(&services, address(), clock) };
        assert!(matches!(
            result,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert_eq!(*services.requests.borrow(), [address()]);
        assert_eq!(*services.preparations.borrow(), [address()]);
    }

    #[test]
    fn a_refused_claim_attaches_nothing_and_keeps_no_owner() {
        let services = Refusing::minimum_only();
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        // SAFETY: the refusing services transfer no owner.
        let tg3 = unsafe { tg3(&services, address()) };
        assert!(matches!(
            tg3,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert_eq!(*services.preparations.borrow(), [address()]);
        // SAFETY: as above.
        let aqtion = unsafe { aqtion(&services, address()) };
        assert!(matches!(
            aqtion,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert_eq!(*services.preparations.borrow(), [address(); 2]);
        // SAFETY: as above.
        let vmd = unsafe { vmd(&services, address(), clock, &Default::default()) };
        assert!(matches!(
            vmd,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        // VMD attaches through the cold preparation the policy plans for it.
        assert_eq!(*services.preparations.borrow(), [address(); 3]);
        // SAFETY: as above.
        let bluetooth = unsafe { intel_bluetooth(&services, address(), clock) };
        assert!(matches!(
            bluetooth,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert_eq!(*services.requests.borrow(), [address(); 4]);
    }

    #[test]
    fn a_broadcom_function_without_interrupts_claims_nothing() {
        let services = Refusing::minimum_only();
        let clock = Clock {
            ticks_per_microsecond: 1000,
        };
        // SAFETY: an empty topology owns no bridge, and the refusing services
        // transfer no owner.
        let topology =
            unsafe { crate::bus::pci::native_aspm::Topology::new(Vec::new(), Vec::new()) };
        let board = bcm4377::Board::from_dmi("Apple Inc.", "MacBookAir9,1").unwrap();
        // SAFETY: as above.
        let bluetooth = unsafe { bcm4377(&services, address(), topology, board, clock) };
        assert!(matches!(
            bluetooth,
            Err((Error::Native(ServiceError::Unavailable), None))
        ));
        assert!(services.requests.borrow().is_empty());
    }

    /// A refused claim of an RTL8852CE keeps no owner and touches nothing.
    #[test]
    fn a_refused_rtw89_claim_keeps_no_owner() {
        let services = Refusing::minimum_only();
        let realtek_wifi::ax::attach::Inputs {
            clock,
            database,
            network,
            entropy,
        } = station_inputs(None);
        let inputs = Rtw89Inputs {
            firmware: Box::leak(Box::new(crate::firmware::HandoffProvider::new(None))),
            pages: services.pages(),
            clock,
            database,
            network,
            entropy,
        };
        // SAFETY: the refusing services transfer no owner.
        let result = unsafe { rtw89_wifi(&services, address(), inputs) };
        assert!(matches!(
            result,
            Err(Rtw89Down {
                error: Error::Native(ServiceError::Unavailable),
                was_on: false,
                kept: None,
                bus_master: None,
            })
        ));
        // Through the cold preparation, never the sealed stopped claim.
        assert_eq!(*services.preparations.borrow(), [address()]);
    }

    /// What an RTL8852CE attach did, in order.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Read(u32),
        Write(u32, u32),
        Finalize,
        Master,
        /// Bus Master cleared after a failed station attach.
        Unmaster,
    }

    /// An RTL8852CE register window: R_AX_IC_PWR_STATE reads `mac` until
    /// the power-off's coex scoreboard write, then off; every power poll is
    /// satisfied at once; everything else reads zero. Time advances with
    /// every look at the clock, so every other poll ends.
    struct Chip {
        events: Vec<Event>,
        mac: u32,
        now: u64,
    }
    impl Chip {
        fn read(&mut self, reg: u32) -> u32 {
            self.events.push(Event::Read(reg));
            match reg {
                0x03F0 => self.mac,
                // RDY_SYSPWR set, APFN_ONMAC and APFM_OFFMAC clear.
                0x0004 => 1 << 17,
                _ => 0,
            }
        }
        fn write(&mut self, reg: u32, value: u32) {
            self.events.push(Event::Write(reg, value));
            if (reg, value) == (0x00AF, 0x80) {
                self.mac = 0;
            }
        }
    }
    impl AxIo for Chip {
        fn read8(&mut self, reg: u32) -> Result<u8, AxError> {
            Ok(self.read(reg) as u8)
        }
        fn read16(&mut self, reg: u32) -> Result<u16, AxError> {
            Ok(self.read(reg) as u16)
        }
        fn read32(&mut self, reg: u32) -> Result<u32, AxError> {
            Ok(self.read(reg))
        }
        fn write8(&mut self, reg: u32, v: u8) -> Result<(), AxError> {
            self.write(reg, v.into());
            Ok(())
        }
        fn write16(&mut self, reg: u32, v: u16) -> Result<(), AxError> {
            self.write(reg, v.into());
            Ok(())
        }
        fn write32(&mut self, reg: u32, v: u32) -> Result<(), AxError> {
            self.write(reg, v);
            Ok(())
        }
        fn delay_us(&mut self, us: u64) {
            self.now += us;
        }
        fn now_us(&mut self) -> Result<u64, AxError> {
            self.now += 10;
            Ok(self.now)
        }
    }

    /// A domain that maps nothing.
    struct NoDomain;
    // SAFETY: refuses every operation; nothing is ever mapped.
    unsafe impl DmaDomain for NoDomain {
        unsafe fn map(
            &self,
            _: &crate::bus::dma::pages::DmaPages,
            _: crate::bus::dma::mapping::Direction,
            _: u64,
        ) -> Result<crate::bus::dma::mapping::DomainMapping, crate::bus::dma::mapping::DmaError>
        {
            Err(crate::bus::dma::mapping::DmaError::MappingFailed)
        }
        unsafe fn unmap(
            &self,
            _: crate::bus::dma::mapping::DomainMapping,
        ) -> Result<(), crate::bus::dma::mapping::DmaError> {
            Err(crate::bus::dma::mapping::DmaError::InvalidationFailed)
        }
        unsafe fn sync_for_device(
            &self,
            _: crate::bus::dma::mapping::DomainMapping,
            _: core::ops::Range<usize>,
            _: crate::bus::dma::mapping::Direction,
        ) -> Result<(), crate::bus::dma::mapping::DmaError> {
            Err(crate::bus::dma::mapping::DmaError::MappingFailed)
        }
        unsafe fn sync_for_cpu(
            &self,
            _: crate::bus::dma::mapping::DomainMapping,
            _: core::ops::Range<usize>,
            _: crate::bus::dma::mapping::Direction,
        ) -> Result<(), crate::bus::dma::mapping::DmaError> {
            Err(crate::bus::dma::mapping::DmaError::MappingFailed)
        }
    }

    /// The device side of an attach over [`Chip`]: finalization and Bus
    /// Master are recorded among the register accesses, and finalization
    /// fails when `refuse` says so.
    struct Device {
        chip: Chip,
        refuse: bool,
    }
    impl Rtw89Device for Device {
        type Io = Chip;
        fn io(&mut self) -> &mut Chip {
            &mut self.chip
        }
        fn host(&self) -> Host {
            Host { ltr: false }
        }
        unsafe fn finalize(&mut self) -> Result<Arc<dyn DmaDomain>, Error> {
            self.chip.events.push(Event::Finalize);
            if self.refuse {
                return Err(Error::Native(ServiceError::Refused("model refusal")));
            }
            Ok(Arc::new(NoDomain))
        }
        fn master(&mut self) -> Result<(), Error> {
            self.chip.events.push(Event::Master);
            Ok(())
        }
    }

    /// An RTL8852CE, cut 2 (CBV) in SYS_CFG1.
    fn rtl8852ce() -> realtek_wifi::identity::Observed {
        realtek_wifi::identity::Observed {
            vendor: 0x10ec,
            device: 0xc852,
            subsystem_vendor: 0x1043,
            subsystem_device: 0x1b0d,
            pci_revision: 0,
            sys_cfg1: 2 << 12,
        }
    }

    /// A catalog holding `bytes` as `rtw89/rtw8852c_fw-2.bin` for the chip.
    fn catalog(bytes: Vec<u8>) -> crate::firmware::Catalog {
        catalog_for("pci:10ec:c852", bytes)
    }

    /// A catalog holding `bytes` as `rtw89/rtw8852c_fw-2.bin`, bound to
    /// `hardware`.
    fn catalog_for(hardware: &str, bytes: Vec<u8>) -> crate::firmware::Catalog {
        use sha2::{Digest, Sha256};
        crate::firmware::Catalog::from_handoff(alloc::vec![crate::firmware::Resource {
            name: "rtw89/rtw8852c_fw-2.bin",
            target: crate::firmware::Target {
                driver: "realtek-wifi",
                hardware,
                revision: realtek_wifi::identity::CHIP_REVISION,
                board: None,
            },
            provenance: crate::firmware::Provenance {
                source: "synthetic-fixtures",
                revision: "v1",
                member: "fixtures/rtw8852c_fw-2.bin",
                license: "CC0-1.0",
            },
            expected_length: bytes.len(),
            expected_sha256: Sha256::digest(&bytes).into(),
            bytes,
        }])
        .unwrap()
    }

    /// The smallest image rtw89 accepts, a v0 header with no section, as
    /// the one cut-0 normal entry of an MFW container, followed by every
    /// PHY table the bring-up requires: BB, BB gain, radio B in slot 0, radio
    /// A in slot 1 and NCTL.
    fn empty_image() -> crate::firmware::Catalog {
        // Then an empty table for each TX power and REGD element the
        // bring-up reads after the efuse (by rate, the 2.4 and 5 GHz limits
        // and RU limits, the TX shape, REGD): rfe 0, no entries.
        catalog(container(&[
            (2, 0),
            (3, 0),
            (5, 0),
            (4, 1),
            (8, 0),
            (9, 0),
            (10, 0),
            (11, 0),
            (13, 0),
            (14, 0),
            (16, 0),
            (20, 0),
        ]))
    }

    /// An MFW container (fw.c:668-691) whose one entry, cut 0 and type
    /// NORMAL, is a 32-byte v0 header, then one element per `(id, idx)`,
    /// each holding the single pair RF 0x05 = 0 (fw.c:1560-1612).
    fn container(elements: &[(u32, u8)]) -> Vec<u8> {
        let mut b = alloc::vec![0u8; 32];
        b[0] = 0xff;
        b[1] = 1;
        b[17] = 1;
        b[20..24].copy_from_slice(&32u32.to_le_bytes());
        b[24..28].copy_from_slice(&32u32.to_le_bytes());
        b.extend_from_slice(&[0; 32]);
        for &(id, idx) in elements {
            b.extend_from_slice(&id.to_le_bytes());
            b.extend_from_slice(&8u32.to_le_bytes());
            b.extend_from_slice(&[0; 4 + 2 + 10]);
            b.push(idx);
            b.extend_from_slice(&[0; 7]);
            b.extend_from_slice(&[5, 0, 0, 0, 0, 0, 0, 0]);
            b.resize(b.len().next_multiple_of(16), 0);
        }
        b
    }

    /// What [`rtw89_attach`] returns.
    type Attached = Result<(Running, Rings, bool), (Error, bool)>;

    /// Run [`rtw89_attach`] on a chip whose MAC reads `mac`.
    fn attach(
        mac: u32,
        refuse: bool,
        firmware: &dyn crate::firmware::Provider,
    ) -> (Vec<Event>, Attached) {
        let mut device = Device {
            chip: Chip {
                events: Vec::new(),
                mac,
                now: 0,
            },
            refuse,
        };
        let services = Refusing::default();
        // SAFETY: `Device` is a model, not a device, and `NoDomain` maps
        // nothing, so nothing is programmed anywhere.
        let result = unsafe { rtw89_attach(&mut device, rtl8852ce(), firmware, services.pages()) };
        (device.chip.events, result)
    }

    fn position(events: &[Event], event: Event) -> usize {
        events.iter().position(|found| *found == event).unwrap()
    }

    /// A stick without `rtw89/rtw8852c_fw-2.bin` fails the attach at its
    /// firmware with no register access, binding or Bus Master, and the boot
    /// log names the file once.
    #[test]
    fn missing_firmware_fails_before_any_register_access() {
        let (events, result) = attach(0, false, &crate::firmware::HandoffProvider::new(None));
        let Err((error, false)) = result else {
            panic!("an RTL8852CE came up with no firmware, or its MAC read on")
        };
        assert!(events.is_empty(), "{events:x?}");
        assert!(matches!(
            error,
            Error::Rtw89Wifi(BringUpError {
                step: "firmware",
                error: AxError::FirmwareFile("rtw89/rtw8852c_fw-2.bin is not on the USB stick"),
                ..
            })
        ));
        let at = address();
        // Filed under Wi-Fi by its kind, and printed as stela-boot's
        // `report_failure` prints it.
        let devices = crate::probe::Devices::default();
        assert_eq!(
            alloc::format!(
                "HOST DEVICE FAILED pci={at} ({}) error={error}",
                devices.subsystem(at, &error)
            ),
            "HOST DEVICE FAILED pci=0000:03:00.0 (Wi-Fi) error=rtw89: RTL8852CE bring-up: \
             firmware: rtw89/rtw8852c_fw-2.bin is not on the USB stick"
        );
        assert_eq!(
            alloc::format!("{}", super::super::plain(&error)),
            "RTL8852CE bring-up: firmware: rtw89/rtw8852c_fw-2.bin is not on the USB stick"
        );
    }

    /// A file that is not an rtw89 image (its header version byte reads
    /// 0x5a) fails the same way, with its own reason.
    #[test]
    fn malformed_firmware_fails_before_any_register_access() {
        let catalog = catalog(alloc::vec![0x5a; 64]);
        let (events, result) = attach(
            0,
            false,
            &crate::firmware::HandoffProvider::new(Some(&catalog)),
        );
        assert!(events.is_empty(), "{events:x?}");
        let Err((error, false)) = result else {
            panic!("an RTL8852CE came up on a malformed image, or its MAC read on")
        };
        assert_eq!(
            alloc::format!("{error}"),
            "rtw89: RTL8852CE bring-up: firmware: rtw89/rtw8852c_fw-2.bin has a firmware header \
             version other than 0"
        );
    }

    /// A file whose elements cannot be walked, or that lacks a PHY table the
    /// bring-up applies, fails the attach at `"phy tables"` before the
    /// quiescence, with no register access.
    #[test]
    fn rtw89_attach_refuses_firmware_without_phy_tables() {
        for (bytes, line) in [
            (
                // A plain image with no MFW container: no elements at all.
                alloc::vec![0; 32],
                "rtw89: RTL8852CE bring-up: phy tables: rtw89/rtw8852c_fw-2.bin elements are \
                 unreadable",
            ),
            (
                container(&[]),
                "rtw89: RTL8852CE bring-up: phy tables: firmware carries no BB table",
            ),
            (
                container(&[(2, 0), (3, 0), (5, 0), (4, 1)]),
                "rtw89: RTL8852CE bring-up: phy tables: firmware carries no NCTL table",
            ),
            (
                container(&[(2, 0), (3, 0), (4, 0), (5, 1), (8, 0)]),
                "rtw89: RTL8852CE bring-up: phy tables: firmware radio slots are not B then A",
            ),
        ] {
            let catalog = catalog(bytes);
            let (events, result) = attach(
                0x100,
                false,
                &crate::firmware::HandoffProvider::new(Some(&catalog)),
            );
            assert!(events.is_empty(), "{line}: {events:x?}");
            let Err((error, false)) = result else {
                panic!("{line}: an RTL8852CE came up without its PHY tables")
            };
            assert!(
                matches!(
                    error,
                    Error::Rtw89Wifi(BringUpError {
                        step: "phy tables",
                        ..
                    })
                ),
                "{line}"
            );
            assert_eq!(alloc::format!("{error}"), line);
        }
    }

    /// A chip whose MAC reads off is only looked at before its quiescence
    /// is acknowledged; the binding comes before Bus Master, and Bus Master
    /// before the bring-up's first register write.
    #[test]
    fn quiescence_is_acknowledged_and_finalized_before_bus_master() {
        let catalog = empty_image();
        let (events, result) = attach(
            0,
            false,
            &crate::firmware::HandoffProvider::new(Some(&catalog)),
        );
        assert_eq!(
            events[..3],
            [Event::Read(0x03F0), Event::Finalize, Event::Master]
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::Master)
                .count(),
            1
        );
        // The bring-up ran past power-on on the bound domain, whose model
        // maps nothing.
        assert!(events.len() > 3);
        assert!(matches!(
            result,
            Err((Error::Rtw89Wifi(BringUpError { step, .. }), false))
                if step != "firmware" && step != "quiesce"
        ));
    }

    /// A chip left on is powered off, coex told last, before its
    /// quiescence is acknowledged; nothing is written before that. The
    /// bring-up after it fails here (the model domain maps nothing), and the
    /// failure still says the MAC was left on.
    #[test]
    fn a_chip_left_on_is_powered_off_before_the_acknowledgement() {
        let catalog = empty_image();
        let (events, result) = attach(
            0x100,
            false,
            &crate::firmware::HandoffProvider::new(Some(&catalog)),
        );
        assert!(matches!(result, Err((Error::Rtw89Wifi(_), true))));
        let finalize = position(&events, Event::Finalize);
        assert_eq!(events[0], Event::Read(0x03F0));
        let before = &events[..finalize];
        let writes: Vec<_> = before
            .iter()
            .filter(|event| matches!(event, Event::Write(..)))
            .collect();
        // The PCIe WPDMA stops first: STOP_WPDMA (0x1010 bit19), then the
        // AXI master stopped (0x1000 bit17) and TX/RX HCI DMA cleared.
        assert_eq!(writes[0], &Event::Write(0x1010, 1 << 19));
        assert_eq!(writes[1], &Event::Write(0x1000, 1 << 17));
        assert!(
            matches!(writes[2], Event::Write(0x1000, value) if value & (1 << 7 | 1 << 15) == 0)
        );
        // Then rtw8852c_pwr_off_func, its first write an XTAL SI command and
        // its last setting APFM_SWLPS (0x0004 bit10), then the scoreboard.
        assert!(matches!(writes[3], Event::Write(0x0270, _)));
        assert!(writes.contains(&&Event::Write(0x0004, 1 << 17 | 1 << 10)));
        assert_eq!(writes.last(), Some(&&Event::Write(0x00AF, 0x80)));
        assert!(!before.contains(&Event::Master));
        assert_eq!(events[finalize + 1], Event::Master);
    }

    /// A MAC in LPS, its firmware alive, or in the undefined state 3 is never
    /// taken as stopped: nothing is written, the quiescence is never
    /// acknowledged and Bus Master stays sealed off.
    #[test]
    fn a_mac_in_lps_or_an_undefined_state_is_never_finalized() {
        let catalog = empty_image();
        for (mac, state) in [(0x200, 2), (0x300, 3)] {
            let (events, result) = attach(
                mac,
                false,
                &crate::firmware::HandoffProvider::new(Some(&catalog)),
            );
            assert_eq!(events, [Event::Read(0x03F0)], "{mac:#x}");
            let Err((error, false)) = result else {
                panic!("a MAC in state {state} came up, or was taken as on")
            };
            assert!(matches!(
                error,
                Error::Rtw89Wifi(BringUpError {
                    step: "quiesce",
                    error: AxError::MacPowerState(found),
                    ..
                }) if found == state
            ));
            if state == 2 {
                let at = address();
                let devices = crate::probe::Devices::default();
                assert_eq!(
                    alloc::format!(
                        "HOST DEVICE FAILED pci={at} ({}) error={error}",
                        devices.subsystem(at, &error)
                    ),
                    "HOST DEVICE FAILED pci=0000:03:00.0 (Wi-Fi) error=rtw89: RTL8852CE bring-up: \
                     quiesce: the MAC is in firmware-managed low power (LPS), so its firmware may \
                     still run; Bus Master stays off; power the machine fully off (not restart) \
                     and boot again"
                );
            }
        }
    }

    /// The file on the stick, bound to another adapter, is named as such.
    #[test]
    fn firmware_for_another_adapter_is_named_as_such() {
        let catalog = catalog_for("pci:10ec:b852", alloc::vec![0; 32]);
        let (events, result) = attach(
            0,
            false,
            &crate::firmware::HandoffProvider::new(Some(&catalog)),
        );
        assert!(events.is_empty(), "{events:x?}");
        let Err((error, false)) = result else {
            panic!("an RTL8852CE came up on the firmware of another adapter, or its MAC read on")
        };
        assert_eq!(
            alloc::format!("{error}"),
            "rtw89: RTL8852CE bring-up: firmware: rtw89/rtw8852c_fw-2.bin is on the USB stick \
             only for another adapter, neither this one nor the RTL8852CE chip binding"
        );
    }

    /// A function firmware left in D3hot is brought to D0 before its BARs
    /// are sized.
    #[test]
    fn d0_is_restored_before_the_bars_are_sized() {
        let Ok(mut function) = Function::new(address(), Config::d3hot()) else {
            panic!("the configuration fixture is a function")
        };
        let minimum = crate::minimum_model::owned(Clock {
            ticks_per_microsecond: 1000,
        });
        // Only the order is checked: the BARs of the fixture are not real.
        let _ = rtw89_wake(&mut function, minimum.as_ref());
        let writes = &function.config().1;
        let pmcsr = writes.iter().position(|offset| *offset == 0x44);
        let sizing = writes
            .iter()
            .position(|offset| (0x10..0x28).contains(offset));
        assert!(pmcsr.is_some() && sizing.is_some(), "{writes:x?}");
        assert!(pmcsr < sizing, "{writes:x?}");
        assert_eq!(function.config().0[0x44 / 4] & 3, 0);
    }

    /// A refused finalization leaves Bus Master clear.
    #[test]
    fn a_refused_finalization_never_masters() {
        let catalog = empty_image();
        let (events, result) = attach(
            0,
            true,
            &crate::firmware::HandoffProvider::new(Some(&catalog)),
        );
        assert_eq!(events, [Event::Read(0x03F0), Event::Finalize]);
        assert!(matches!(
            result,
            Err((Error::Native(ServiceError::Refused("model refusal")), false))
        ));
    }

    /// A function whose IDs name another chip fails its identity, with no
    /// firmware wording.
    #[test]
    fn another_chip_is_refused_by_its_identity() {
        let observed = realtek_wifi::identity::Observed {
            device: 0xb852,
            ..rtl8852ce()
        };
        let Err(error) = rtw89_stage(observed, &crate::firmware::HandoffProvider::new(None)) else {
            panic!("an RTL8852BE was staged as an RTL8852CE")
        };
        assert_eq!(
            alloc::format!("{error}"),
            "RTL8852CE bring-up: identity: its PCI vendor and device IDs are not the RTL8852CE's \
             10ec:c852"
        );
    }

    /// An RTL8852CE configuration space with MSI enabled by firmware:
    /// subsystem 1043:1b0d, revision 0, and an MSI capability at 0x50.
    struct Config([u32; 64], Vec<u16>);
    impl Config {
        /// As [`Self::new`], with a power management capability at 0x40
        /// whose PMCSR says D3hot.
        fn d3hot() -> Self {
            let mut config = Self::new();
            config.0[0x34 / 4] = 0x40;
            // PM: ID 1, next 0x50; PMCSR D3hot.
            config.0[0x40 / 4] = 0x03 << 16 | 0x50 << 8 | 0x01;
            config.0[0x44 / 4] = 3;
            config
        }
        fn new() -> Self {
            let mut words = [0; 64];
            words[0] = 0xc852_10ec;
            // Status: capabilities list.
            words[1] = 0x0010 << 16;
            words[2] = 0x0280_0000;
            words[0x2c / 4] = 0x1b0d_1043;
            words[0x34 / 4] = 0x50;
            // MSI: ID 5, last, 64-bit, enabled.
            words[0x50 / 4] = (1 << 7 | 1) << 16 | 0x05;
            Self(words, Vec::new())
        }
        fn command(&self) -> u16 {
            self.0[1] as u16
        }
        fn msi_enabled(&self) -> bool {
            self.0[0x50 / 4] & 1 << 16 != 0
        }
    }
    impl ConfigSpace for Config {
        fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
            Ok((self.0[usize::from(offset / 4)] >> (offset % 4 * 8)) as u8)
        }
        fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
            Ok((self.0[usize::from(offset / 4)] >> (offset % 4 * 8)) as u16)
        }
        fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
            Ok(self.0[usize::from(offset / 4)])
        }
        fn write8(&mut self, offset: u16, value: u8) -> Result<(), crate::bus::pci::ConfigError> {
            self.1.push(offset);
            let word = &mut self.0[usize::from(offset / 4)];
            let shift = offset % 4 * 8;
            *word = *word & !(0xff << shift) | u32::from(value) << shift;
            Ok(())
        }
        fn write16(&mut self, offset: u16, value: u16) -> Result<(), crate::bus::pci::ConfigError> {
            self.1.push(offset);
            let word = &mut self.0[usize::from(offset / 4)];
            let shift = offset % 4 * 8;
            *word = *word & !(0xffff << shift) | u32::from(value) << shift;
            Ok(())
        }
        fn write32(&mut self, offset: u16, value: u32) -> Result<(), crate::bus::pci::ConfigError> {
            self.1.push(offset);
            self.0[usize::from(offset / 4)] = value;
            Ok(())
        }
    }

    /// Before the binding, the attach turns memory decode on and MSI off
    /// and leaves Bus Master clear; after it, Bus Master goes on and MSI
    /// stays off.
    #[test]
    fn rtw89_decodes_without_bus_master_and_masters_without_msi() {
        let Ok(mut function) = Function::new(address(), Config::new()) else {
            panic!("the configuration fixture is a function")
        };
        assert_eq!(
            rtw89_decode(&mut function).unwrap(),
            (0x1043, 0x1b0d, 0, Host { ltr: false })
        );
        let command = function.config().command();
        assert_eq!(command & 0x0406, 0x0402, "{command:#x}");
        assert!(!function.config().msi_enabled());
        rtw89_master(&mut function).unwrap();
        let command = function.config().command();
        assert_eq!(command & 0x0406, 0x0406, "{command:#x}");
        assert!(!function.config().msi_enabled());
    }

    /// `rtw89_pci_dev_ltr_enabled` (`pci.c:3042`): bit 10 of DEVCTL2, at
    /// 0x28 into the PCIe capability, `PCI_EXP_DEVCTL2_LTR_EN`. A function
    /// without a PCIe capability, or with a version 1 one (which has no
    /// DEVCTL2), reads false, as `pcie_capability_read_word` gives Linux 0
    /// for both.
    #[test]
    fn rtw89_decode_reads_ltr_from_devctl2() {
        // The PCIe capability at 0x70, after MSI: ID 0x10, last, version
        // `version` in its flags; DEVCTL2 at 0x98 reads `devctl2`.
        let express = |version: u32, devctl2: u32| {
            let mut config = Config::new();
            config.0[0x50 / 4] |= 0x70 << 8;
            config.0[0x70 / 4] = version << 16 | 0x10;
            config.0[0x98 / 4] = devctl2;
            config
        };
        for (config, ltr) in [
            (express(2, 0x0400), true),
            (express(2, 0x0000), false),
            (express(2, 0xFBFF), false),
            (express(1, 0x0400), false),
            (Config::new(), false),
        ] {
            let Ok(mut function) = Function::new(address(), config) else {
                panic!("the configuration fixture is a function")
            };
            let (_, _, _, host) = rtw89_decode(&mut function).unwrap();
            assert_eq!(host, Host { ltr });
        }
    }

    /// Zeroed, aligned heap pages standing in for the mount's coherent WB
    /// RAM. No device reaches them: the model below only records registers.
    struct HeapPages {
        pointer: core::ptr::NonNull<u8>,
        layout: core::alloc::Layout,
        physical: Vec<u64>,
    }
    // SAFETY: an exclusively kept test allocation; nothing aliases it
    // across threads.
    unsafe impl Send for HeapPages {}
    // SAFETY: as for `Send`; no reference into it is handed out.
    unsafe impl Sync for HeapPages {}
    // SAFETY: `cpu_base` and `physical` describe the one kept, aligned
    // allocation for its whole life.
    unsafe impl crate::bus::dma::memory::PageBacking for HeapPages {
        fn cpu_base(&self) -> core::ptr::NonNull<u8> {
            self.pointer
        }
        fn physical_pages(&self) -> &[u64] {
            &self.physical
        }
        fn page_shift(&self) -> u8 {
            12
        }
        fn cache_attribute(&self) -> crate::bus::dma::memory::CacheAttribute {
            crate::bus::dma::memory::CacheAttribute::WriteBack
        }
    }
    impl Drop for HeapPages {
        fn drop(&mut self) {
            // SAFETY: the pointer came from `alloc_zeroed` with this layout
            // and is freed once.
            unsafe { alloc::alloc::dealloc(self.pointer.as_ptr(), self.layout) };
        }
    }
    struct Heap;
    impl PageSource for Heap {
        fn allocate(
            &self,
            bytes: usize,
            alignment: usize,
            attribute: crate::bus::dma::memory::CacheAttribute,
        ) -> Result<crate::bus::dma::memory::PinnedPages, crate::bus::dma::memory::MemoryError>
        {
            use crate::bus::dma::memory::{CacheAttribute, MemoryError, PinnedPages};
            assert_eq!(attribute, CacheAttribute::WriteBack);
            let rounded = bytes.next_multiple_of(4096);
            let layout = core::alloc::Layout::from_size_align(rounded, alignment.max(4096))
                .map_err(|_| MemoryError::OutOfMemory)?;
            // SAFETY: the layout has a nonzero size.
            let pointer = core::ptr::NonNull::new(unsafe { alloc::alloc::alloc_zeroed(layout) })
                .ok_or(MemoryError::OutOfMemory)?;
            let physical = (0..rounded / 4096)
                .map(|i| pointer.as_ptr() as u64 + i as u64 * 4096)
                .collect();
            PinnedPages::new(
                Box::new(HeapPages {
                    pointer,
                    layout,
                    physical,
                }),
                bytes,
                alignment,
            )
        }
    }

    /// A domain that hands out IOVAs below 4 GiB; syncs succeed. Nothing
    /// reads or writes through it.
    #[derive(Default)]
    struct Counting(core::sync::atomic::AtomicU64);
    // SAFETY: a model domain: the bring-up's allocations keep their own
    // pins, and no device reaches the addresses it hands out.
    unsafe impl DmaDomain for Counting {
        unsafe fn map(
            &self,
            pages: &crate::bus::dma::pages::DmaPages,
            _: crate::bus::dma::mapping::Direction,
            _: u64,
        ) -> Result<crate::bus::dma::mapping::DomainMapping, crate::bus::dma::mapping::DmaError>
        {
            let pin = pages
                .as_single()
                .ok_or(crate::bus::dma::mapping::DmaError::MappingFailed)?;
            let next = self
                .0
                .fetch_add(0x10000, core::sync::atomic::Ordering::Relaxed);
            let address = 0x1001_0000 + next;
            Ok(crate::bus::dma::mapping::DomainMapping {
                id: address,
                address,
                bytes: pin.bytes(),
            })
        }
        unsafe fn unmap(
            &self,
            _: crate::bus::dma::mapping::DomainMapping,
        ) -> Result<(), crate::bus::dma::mapping::DmaError> {
            Ok(())
        }
        unsafe fn sync_for_device(
            &self,
            _: crate::bus::dma::mapping::DomainMapping,
            _: core::ops::Range<usize>,
            _: crate::bus::dma::mapping::Direction,
        ) -> Result<(), crate::bus::dma::mapping::DmaError> {
            Ok(())
        }
        unsafe fn sync_for_cpu(
            &self,
            _: crate::bus::dma::mapping::DomainMapping,
            _: core::ops::Range<usize>,
            _: crate::bus::dma::mapping::Direction,
        ) -> Result<(), crate::bus::dma::mapping::DmaError> {
            Ok(())
        }
    }

    /// An RTL8852CE register file every bring-up step up to OFLD_CFG passes
    /// on: written values read back, power and XTAL SI polls complete, the
    /// efuse reads blank (secure boot off), the DLE managers and STA
    /// scheduler report ready, the CAM resets self-clear, CH12 consumes
    /// every kick, and once the WCPU is enabled the firmware reports ready.
    /// RXQ never fills, so the bring-up ends at `"c2h"`, after post-init.
    struct Live {
        regs: alloc::collections::BTreeMap<u32, u8>,
        writes: Vec<(u32, u32)>,
        now: u64,
    }
    impl Live {
        fn new() -> Self {
            let mut live = Self {
                regs: alloc::collections::BTreeMap::new(),
                writes: Vec::new(),
                now: 0,
            };
            live.put(0x179C, 4, 0x0C9C);
            live
        }
        fn get(&self, reg: u32, width: u32) -> u32 {
            (0..width).fold(0, |v, i| {
                v | u32::from(*self.regs.get(&(reg + i)).unwrap_or(&0)) << (8 * i)
            })
        }
        fn put(&mut self, reg: u32, width: u32, value: u32) {
            for i in 0..width {
                self.regs.insert(reg + i, (value >> (8 * i)) as u8);
            }
        }
        fn read(&mut self, reg: u32, width: u32) -> u32 {
            let v = self.get(reg, 4);
            let v = match reg {
                0x0004 => (v | 1 << 17) & !(1 << 8 | 1 << 9),
                0x0270 => v & 0x7FFF_FFFF,
                0x0030 => (v & 0x07FF_0000) | 1 << 29 | 0xFF,
                0x8D00 | 0x9100 => 3,
                0x1000 => v & !(1 << 3),
                0x1080 => (v & 0xFFF) | (v & 0xFFF) << 16,
                0x01E0 if self.get(0x0088, 4) & 1 << 1 != 0 => (v & !0xE0) | 7 << 5 | 0x6,
                0x9E10 => v | 0x8000_0000,
                0xCE34 => v & !0x100,
                0xCE3C => v & !0x3,
                _ => v,
            };
            self.put(reg, 4, v);
            self.get(reg, width)
        }
        fn write(&mut self, reg: u32, width: u32, value: u32) {
            self.writes.push((reg, value));
            self.put(reg, width, value);
        }
    }
    impl AxIo for Live {
        fn read8(&mut self, reg: u32) -> Result<u8, AxError> {
            Ok(self.read(reg, 1) as u8)
        }
        fn read16(&mut self, reg: u32) -> Result<u16, AxError> {
            Ok(self.read(reg, 2) as u16)
        }
        fn read32(&mut self, reg: u32) -> Result<u32, AxError> {
            Ok(self.read(reg, 4))
        }
        fn write8(&mut self, reg: u32, v: u8) -> Result<(), AxError> {
            self.write(reg, 1, v.into());
            Ok(())
        }
        fn write16(&mut self, reg: u32, v: u16) -> Result<(), AxError> {
            self.write(reg, 2, v.into());
            Ok(())
        }
        fn write32(&mut self, reg: u32, v: u32) -> Result<(), AxError> {
            self.write(reg, 4, v);
            Ok(())
        }
        fn delay_us(&mut self, us: u64) {
            self.now += us;
        }
        fn now_us(&mut self) -> Result<u64, AxError> {
            Ok(self.now)
        }
    }

    /// The device side of an attach over [`Live`], bound to a [`Counting`]
    /// domain, whose preparation read `host`.
    struct LiveDevice {
        chip: Live,
        host: Host,
    }
    impl Rtw89Device for LiveDevice {
        type Io = Live;
        fn io(&mut self) -> &mut Live {
            &mut self.chip
        }
        fn host(&self) -> Host {
            self.host
        }
        unsafe fn finalize(&mut self) -> Result<Arc<dyn DmaDomain>, Error> {
            Ok(Arc::new(Counting::default()))
        }
        fn master(&mut self) -> Result<(), Error> {
            Ok(())
        }
    }

    /// The `Host` an attach's device reports reaches `bring_up`: with
    /// `ltr: true` the post-init programs the LTR decision register
    /// (`R_AX_LTR_DEC_CTRL`, 0x1600) and the deinit clears it again; with
    /// `ltr: false` it is never written.
    #[test]
    fn the_prepared_ltr_flag_reaches_the_bring_up() {
        let catalog = empty_image();
        for ltr in [true, false] {
            let mut device = LiveDevice {
                chip: Live::new(),
                host: Host { ltr },
            };
            // SAFETY: `LiveDevice` is a model, not a device: `Counting`
            // keeps every pin and no device reaches its addresses, and
            // `Heap` is plain test memory.
            let result = unsafe {
                rtw89_attach(
                    &mut device,
                    rtl8852ce(),
                    &crate::firmware::HandoffProvider::new(Some(&catalog)),
                    &Heap,
                )
            };
            // The model's RXQ never fills: the bring-up ran through
            // post-init and failed waiting for the firmware's answer.
            let Err((Error::Rtw89Wifi(BringUpError { step, .. }), false)) = result else {
                panic!("the modeled bring-up did not fail at its C2H wait")
            };
            assert_eq!(step, "c2h");
            let ltr_writes: Vec<u32> = device
                .chip
                .writes
                .iter()
                .filter(|(reg, _)| *reg == 0x1600)
                .map(|(_, value)| *value)
                .collect();
            if ltr {
                // ltr_set_v1(true), HW_DEC_EN set; then ltr_set_v1(false).
                assert_eq!(ltr_writes.len(), 2, "{ltr_writes:x?}");
                assert_ne!(ltr_writes[0] & 1 << 2, 0);
                assert_eq!(ltr_writes[1] & 1 << 2, 0);
            } else {
                assert!(ltr_writes.is_empty(), "{ltr_writes:x?}");
            }
        }
    }

    /// `rtw8852ce_id_table`'s one device, as a Wi-Fi function, goes to the
    /// rtw89 bring-up; RTL8822C keeps rtw88's, and another class nothing.
    #[test]
    fn c852_routes_to_rtw89_kind() {
        let identity = |device, class| crate::bus::pci::Identity {
            address: address(),
            vendor: 0x10ec,
            device,
            class,
        };
        let kind = Kind::of_identity(&identity(0xc852, [2, 0x80, 0]));
        assert_eq!(kind, Some(Kind::Rtw89Wifi));
        assert_eq!(kind.unwrap().driver(), "rtw89 Wi-Fi (with --wifi)");
        assert_eq!(
            Kind::of_identity(&identity(0xc822, [2, 0x80, 0])),
            Some(Kind::RealtekWifi)
        );
        assert_eq!(Kind::of_identity(&identity(0xc852, [2, 0, 0])), None);
        // RTL8852BE still has no driver here.
        assert_eq!(Kind::of_identity(&identity(0xb852, [2, 0x80, 0])), None);
    }

    /// The register accesses a model window has seen.
    trait Accesses {
        fn accesses(&self) -> usize;
    }
    impl Accesses for Chip {
        fn accesses(&self) -> usize {
            self.events.len()
        }
    }
    impl Accesses for Live {
        fn accesses(&self) -> usize {
            self.writes.len()
        }
    }

    /// The device side of a normal boot's station attach over a model
    /// window: finalization binds `domain`, and finalization, Bus Master and
    /// its clearing are recorded with the window's accesses before each.
    struct KeptDevice<I> {
        window: Rtw89Window<I>,
        domain: fn() -> Arc<dyn DmaDomain>,
        steps: Vec<(Event, usize)>,
    }
    impl<I: AxIo + Accesses> KeptDevice<I> {
        fn new(io: I, domain: fn() -> Arc<dyn DmaDomain>) -> Self {
            Self {
                window: Rtw89Window::Held(io),
                domain,
                steps: Vec::new(),
            }
        }
        fn step(&mut self, event: Event) {
            let accesses = match &self.window {
                Rtw89Window::Held(io) => io.accesses(),
                Rtw89Window::Taken => usize::MAX,
            };
            self.steps.push((event, accesses));
        }
        fn held(&self) -> &I {
            match &self.window {
                Rtw89Window::Held(io) => io,
                Rtw89Window::Taken => panic!("the station kept the window"),
            }
        }
    }
    impl<I: AxIo + Accesses> Rtw89Device for KeptDevice<I> {
        type Io = Rtw89Window<I>;
        fn io(&mut self) -> &mut Rtw89Window<I> {
            &mut self.window
        }
        fn host(&self) -> Host {
            Host { ltr: false }
        }
        unsafe fn finalize(&mut self) -> Result<Arc<dyn DmaDomain>, Error> {
            self.step(Event::Finalize);
            Ok((self.domain)())
        }
        fn master(&mut self) -> Result<(), Error> {
            self.step(Event::Master);
            Ok(())
        }
    }
    impl<I: AxIo + Accesses> Rtw89Keep for KeptDevice<I> {
        fn unmaster(&mut self) -> Result<(), Error> {
            self.step(Event::Unmaster);
            Ok(())
        }
    }

    fn no_domain() -> Arc<dyn DmaDomain> {
        Arc::new(NoDomain)
    }
    fn counting() -> Arc<dyn DmaDomain> {
        Arc::new(Counting::default())
    }

    /// The plan's test network, in `country`, its secret a PSK so no
    /// passphrase is hashed.
    fn test_network(country: Option<[u8; 2]>) -> crate::net::wifi::network::Network {
        crate::net::wifi::network::Network {
            ssid: b"test".to_vec(),
            secret: crate::net::wifi::network::Secret::parse(&[b'0'; 64]).unwrap(),
            country,
        }
    }

    /// A station's inputs for `country`, regulatory.db holding `00` and
    /// `US` ([`crate::probe::tests::regulatory_database`]).
    fn station_inputs(country: Option<[u8; 2]>) -> realtek_wifi::ax::attach::Inputs {
        realtek_wifi::ax::attach::Inputs {
            clock: Clock {
                ticks_per_microsecond: 1000,
            },
            database: crate::probe::tests::regulatory_database(),
            network: test_network(country),
            entropy: Arc::new(crate::probe::services::tests::NoEntropy),
        }
    }

    /// What [`rtw89_keep`] returns over a model window `I`.
    type KeptOn<I> = Result<
        (
            realtek_wifi::ax::Wifi<realtek_wifi::ax::Live<I>>,
            Running,
            bool,
        ),
        Rtw89Refused,
    >;

    /// Run [`rtw89_keep`] on `device` with `firmware` and `inputs`.
    #[expect(clippy::result_large_err, reason = "rtw89_keep's own result")]
    fn keep_on<I: AxIo + Accesses>(
        device: &mut KeptDevice<I>,
        firmware: &dyn crate::firmware::Provider,
        inputs: realtek_wifi::ax::attach::Inputs,
    ) -> KeptOn<I> {
        // SAFETY: `KeptDevice` is a model, not a device: `NoDomain` maps
        // nothing, `Counting` keeps every pin and no device reaches the
        // addresses it hands out, and `Heap` is plain test memory.
        unsafe { rtw89_keep(device, rtl8852ce(), firmware, &Heap, inputs) }
    }

    fn refused_station<I: AxIo>(kept: KeptOn<I>) -> Rtw89Refused {
        match kept {
            Ok(_) => panic!("a model chip became a station"),
            Err(refused) => refused,
        }
    }

    /// A normal boot's station attach that fails before Bus Master was set
    /// touches no register and still clears Bus Master, last; the window
    /// stays with the device.
    #[test]
    fn a_station_attach_without_firmware_clears_bus_master_untouched() {
        let mut device = KeptDevice::new(
            Chip {
                events: Vec::new(),
                mac: 0,
                now: 0,
            },
            no_domain,
        );
        let refused = refused_station(keep_on(
            &mut device,
            &crate::firmware::HandoffProvider::new(None),
            station_inputs(None),
        ));
        assert!(matches!(
            refused.error,
            Error::Rtw89Wifi(BringUpError {
                step: "firmware",
                ..
            })
        ));
        assert!(!refused.was_on);
        assert!(refused.rings.is_none());
        assert!(refused.bus_master.is_none());
        assert_eq!(device.steps, [(Event::Unmaster, 0)]);
        assert!(device.held().events.is_empty());
    }

    /// A network whose country regulatory.db lacks fails the station's own
    /// check after the take-over, before any register write: the chip
    /// stays off as `quiesce` left it, and Bus Master is cleared again.
    #[test]
    fn a_station_refused_for_its_country_clears_bus_master() {
        let catalog = empty_image();
        let mut device = KeptDevice::new(
            Chip {
                events: Vec::new(),
                mac: 0,
                now: 0,
            },
            no_domain,
        );
        let refused = refused_station(keep_on(
            &mut device,
            &crate::firmware::HandoffProvider::new(Some(&catalog)),
            station_inputs(Some(*b"ZZ")),
        ));
        assert_eq!(
            alloc::format!("{}", refused.error),
            "rtw89: RTL8852CE: regulatory.db country ZZ: Country"
        );
        assert!(refused.rings.is_none());
        // `quiesce` read the MAC off; nothing was written.
        assert_eq!(device.held().events, [Event::Read(0x03F0)]);
        let steps: Vec<Event> = device.steps.iter().map(|(event, _)| *event).collect();
        assert_eq!(steps, [Event::Finalize, Event::Master, Event::Unmaster]);
        assert_eq!(device.steps[2].1, 1);
    }

    /// A station whose start fails past the power-on (the model's RXQ never
    /// answers OFLD_CFG) powers the chip off, hands the window back to the
    /// device with the rings, and only then is Bus Master cleared: nothing
    /// is written after it.
    #[test]
    fn a_station_whose_start_fails_is_powered_off_before_bus_master_clears() {
        let catalog = empty_image();
        let mut device = KeptDevice::new(Live::new(), counting);
        let refused = refused_station(keep_on(
            &mut device,
            &crate::firmware::HandoffProvider::new(Some(&catalog)),
            station_inputs(None),
        ));
        let Error::Rtw89Wifi(BringUpError { step, .. }) = refused.error else {
            panic!("{}", refused.error)
        };
        assert_eq!(step, "c2h");
        assert!(refused.rings.is_some());
        assert!(refused.bus_master.is_none());
        let writes = &device.held().writes;
        // rtw8852c_pwr_off_func's APFM_SWLPS, then the coex scoreboard, last.
        assert_eq!(writes.last(), Some(&(0x00AF, 0x80)));
        let swlps = writes
            .iter()
            .rposition(|&(reg, value)| reg == 0x0004 && value & 1 << 10 != 0);
        assert!(swlps.is_some_and(|at| at + 1 < writes.len()), "{swlps:?}");
        let steps: Vec<Event> = device.steps.iter().map(|(event, _)| *event).collect();
        assert_eq!(steps, [Event::Finalize, Event::Master, Event::Unmaster]);
        assert_eq!(device.steps[2].1, writes.len());
    }

    /// A taken window refuses every access, and answers again once put
    /// back.
    #[test]
    fn a_taken_window_refuses_access_until_put_back() {
        let mut window = Rtw89Window::Held(Chip {
            events: Vec::new(),
            mac: 0x100,
            now: 0,
        });
        let chip = window.take().unwrap();
        assert!(window.take().is_none());
        assert!(matches!(
            window.read32(0x03F0),
            Err(AxError::OutOfWindow { register: 0x03F0 })
        ));
        assert!(matches!(
            window.write8(0x00AF, 0x80),
            Err(AxError::OutOfWindow { register: 0x00AF })
        ));
        assert!(matches!(window.now_us(), Err(AxError::Clock)));
        window.put(chip);
        assert_eq!(window.read32(0x03F0).unwrap(), 0x100);
    }

    /// A chip that answers nothing, for a station that is only looked at.
    struct Idle;
    impl realtek_wifi::ax::station::chip::Chip for Idle {
        fn mac(&self) -> Mac {
            Mac([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
        }
        fn poll(
            &mut self,
            _: &mut dyn FnMut(realtek_wifi::ax::station::chip::Incoming),
        ) -> Result<(), String> {
            Ok(())
        }
        fn tune(&mut self, _: crate::net::wifi::Channel) -> Result<(), String> {
            Err(String::from("idle"))
        }
        fn begin_scan(&mut self, _: &[crate::net::wifi::Channel]) -> Result<(), String> {
            Err(String::from("idle"))
        }
        fn end_scan(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn set_bssid(&mut self, _: Mac) -> Result<(), String> {
            Err(String::from("idle"))
        }
        fn authenticated(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn transmit_management(
            &mut self,
            _: &realtek_wifi::ax::station::chip::Management<'_>,
        ) -> Result<Option<realtek_wifi::ax::station::chip::Token>, String> {
            Ok(None)
        }
        fn transmit_data(
            &mut self,
            _: &realtek_wifi::ax::station::chip::Data<'_>,
        ) -> Result<Option<realtek_wifi::ax::station::chip::Token>, String> {
            Ok(None)
        }
        fn associate(
            &mut self,
            _: &realtek_wifi::ax::station::chip::Association,
        ) -> Result<(), String> {
            Err(String::from("idle"))
        }
        fn disassociate(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn add_key(
            &mut self,
            _: &realtek_wifi::ax::station::chip::HardwareKey<'_>,
        ) -> Result<u8, String> {
            Err(String::from("idle"))
        }
        fn remove_key(&mut self, _: u8) -> Result<(), String> {
            Ok(())
        }
        fn flush(&mut self, _: bool) -> Result<(), String> {
            Ok(())
        }
        fn start_rx_block_ack(&mut self, _: u8, _: u16, _: u16) -> Result<(), String> {
            Ok(())
        }
        fn stop_rx_block_ack(&mut self, _: u8) -> Result<(), String> {
            Ok(())
        }
        fn diagnostic(&self) -> String {
            String::from("idle chip")
        }
    }

    /// A located rtw89 station gives the stack its radio's 30 s carrier
    /// wait (M3 spec S1.5) and its progress line, as the adapter forwards
    /// them (`native.rs` `Located`, `probe.rs` `Adapter`).
    #[test]
    fn a_located_rtw89_station_forwards_its_carrier_wait_and_progress() {
        let country = crate::probe::tests::regulatory_database()
            .select(*b"US")
            .unwrap();
        let radio = realtek_wifi::ax::Rtl8852c::new(
            Idle,
            Mac([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
            country,
            Clock {
                ticks_per_microsecond: 1000,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let mut located = Located {
            location: alloc::format!("{}", address()),
            link: radio.keep(
                test_network(Some(*b"US")),
                Arc::new(crate::probe::services::tests::NoEntropy),
            ),
        };
        assert_eq!(
            located.carrier_wait_us(),
            realtek_wifi::ax::WIFI_CARRIER_WAIT_US
        );
        assert_eq!(located.carrier_wait_us(), 30_000_000);
        let progress = located.diagnostic().unwrap();
        assert!(
            progress.starts_with("scans 0 (0 networks, target -)"),
            "{progress}"
        );
        assert!(!progress.contains("02:11:22"), "{progress}");
        assert!(!located.signals());
    }

    #[test]
    fn broadcom_bluetooth_is_named_by_its_device_table() {
        assert_eq!(
            bcm4377::Chip::of_device(0x5fa0),
            Some(bcm4377::Chip::Bcm4377)
        );
        assert_eq!(
            bcm4377::Chip::of_device(0x5f72),
            Some(bcm4377::Chip::Bcm4388)
        );
        assert_eq!(bcm4377::Chip::of_device(0x4377), None);
    }

    /// A VMD parent's configuration space, by dword.
    struct Parent([u32; 64]);
    impl ConfigSpace for Parent {
        fn read8(&self, offset: u16) -> Result<u8, crate::bus::pci::ConfigError> {
            Ok((self.0[usize::from(offset / 4)] >> (offset % 4 * 8)) as u8)
        }
        fn read16(&self, offset: u16) -> Result<u16, crate::bus::pci::ConfigError> {
            Ok((self.0[usize::from(offset / 4)] >> (offset % 4 * 8)) as u16)
        }
        fn read32(&self, offset: u16) -> Result<u32, crate::bus::pci::ConfigError> {
            Ok(self.0[usize::from(offset / 4)])
        }
        fn write8(&mut self, _: u16, _: u8) -> Result<(), crate::bus::pci::ConfigError> {
            unreachable!()
        }
        fn write16(&mut self, _: u16, _: u16) -> Result<(), crate::bus::pci::ConfigError> {
            unreachable!()
        }
        fn write32(&mut self, _: u16, _: u32) -> Result<(), crate::bus::pci::ConfigError> {
            unreachable!()
        }
    }

    #[test]
    fn a_refused_vmd_host_resource_names_the_bar_words_sizes_and_bus_restriction() {
        // A client host's 64-bit CFGBAR, 32-bit MEMBAR1 and 64-bit MEMBAR2,
        // with buses from e0.
        let mut parent = Parent([0; 64]);
        parent.0[4..10].copy_from_slice(&[0x2c00_0004, 0x62, 0x5000_0000, 0, 0x2f10_0004, 0x62]);
        parent.0[0x10] = 1;
        parent.0[0x11] = 2 << 8;
        let memory = |address, size, wide| {
            Some(Bar::Memory {
                address,
                size,
                prefetchable: false,
                wide,
            })
        };
        let bars = [
            memory(0x62_2c00_0000, 32 << 20, true),
            None,
            memory(0x5000_0000, 32 << 20, false),
            memory(0, 0, false),
            memory(0x62_2f10_0000, 1 << 20, true),
            None,
        ];
        let words = VmdWords::read(&parent, &bars).unwrap();
        let error = Error::VmdResource(vmd::Error::InvalidResource, words);
        assert_eq!(
            alloc::format!("{error}"),
            "VMD: a BAR, window or bus range VMD cannot use; BAR registers 2c000004 00000062 \
             50000000 00000000 2f100004 00000062, sized BAR0 0x622c000000+0x2000000 \
             BAR2 0x50000000+0x2000000 BAR4 0x622f100000+0x100000, VMCAP 0001 VMCONFIG 0200"
        );
    }
}

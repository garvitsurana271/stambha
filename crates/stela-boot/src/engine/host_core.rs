//! The host core (`--host-core on`, `stela_boot_core::host_core`): the
//! reservation's last processor, started as a PE's is and given no PE
//! (`Executors::set_aside_host_core`), runs the host's service turns and the
//! GPUs' pump, so that PE 0's core runs guest code where it served before.
//!
//! It serves as a waiting PE does (`service::serve` with no PE's guest to
//! watch, `gpu::pump_host_core` through the move protocol), so it adds no
//! concurrency rule the waiting PEs do not already follow; `service`'s slot
//! and the pump's turn keep one taker at a time. PE 0 keeps its own
//! fallbacks: it steps the service when nobody served for its starvation
//! limit, and pumps work that waited its longest or that a host core whose
//! beat went stale left ([`takes_pump`]).
//!
//! Before the guest starts the boot processor pings it through the
//! [`Channel`]; without an answer within [`PING_MILLIS`] it never serves and
//! the boot runs as without the option (`HOST CORE fallback`).
use super::{gpu, host, output, service};
use crate::{apic::Apic, native_smp::executor::Executors};
use alloc::{boxed::Box, format, string::String};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use stela_boot_core::host_core::{Channel, Shares, State, Taker, Turn, percent};
use stela_engine::machine::engine::GuestWatch;

static CHANNEL: Channel = Channel::new();

/// The time each taker served, for the beat's share line ([`report`]).
pub(super) static SHARES: Shares = Shares::new();

/// The host core's `host::processor` index, `u32::MAX` before it runs.
static PROCESSOR: AtomicU32 = AtomicU32::new(u32::MAX);
/// The host core's APIC ID, for waking it when GPU work arrives while it
/// sleeps ([`wake_if_sleeping`]).
static APIC_ID: AtomicU32 = AtomicU32::new(u32::MAX);
/// Whether the host core is currently halted in [`pause`].
static SLEEPING: AtomicBool = AtomicBool::new(false);

/// Its passes that ran a service turn, and those that found GPU work ready,
/// since the last [`report`].
static TURNS: AtomicU64 = AtomicU64::new(0);
static PUMPS: AtomicU64 = AtomicU64::new(0);

/// How long the boot processor waits for the ping's answer before it gives
/// the host core up.
const PING_MILLIS: u64 = 50;
/// How long the run's end waits for the host core to acknowledge its stop.
const STOP_MILLIS: u64 = 50;
/// How old the host core's beat may be for PE 0 to leave it the pump.
const STALE_MICROS: u64 = 2000;
/// How often it runs a service turn: about what a waiting PE leaves between
/// two, so the devices' lock is taken no more often than today.
const SERVICE_MICROS: u64 = 500;
/// Its pause between two passes, answering shootdowns.
const PAUSE_MICROS: u64 = 20;

/// Whether this processor is the host core.
pub(super) fn here() -> bool {
    let index = PROCESSOR.load(Ordering::Relaxed);
    index != u32::MAX && index == host::processor()
}

/// Whether a serving host core with a fresh beat takes the GPUs' ready work
/// in its next pass, so PE 0 leaves it.
pub(super) fn takes_pump() -> bool {
    CHANNEL.covers(
        host::fresh_counter(),
        host::COUNTER_HZ / 1_000_000 * STALE_MICROS,
    )
}

/// Wake the host core with a doorbell IPI if it is currently serving and
/// sleeping in [`pause`], so raised GPU work does not wait for the next
/// service timer.
pub(super) fn wake_if_sleeping() -> bool {
    if !takes_pump() || !SLEEPING.load(Ordering::Acquire) {
        return false;
    }
    let apic = APIC_ID.load(Ordering::Relaxed);
    if apic == u32::MAX {
        return false;
    }
    let flags: u64;
    // SAFETY: CPL0 IF save, restored below; ICR write requires interrupts off.
    unsafe { core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags) };
    super::host::ring(apic);
    // SAFETY: the save above, on this processor.
    unsafe { core::arch::asm!("push {}", "popfq", in(reg) flags) };
    true
}

/// Hand the host core its loop and check that it answers, before the
/// guest starts: `pes` PEs run on the others. Nothing without a host core;
/// without an answer the boot goes on as without it.
pub(super) fn start(executors: &Executors, sender: &Apic, tsc_hz: u64, pes: usize) {
    let Some(processor) = executors.host_core() else {
        return;
    };
    let apic = processor.apic_id();
    let slot = processor.slot();
    APIC_ID.store(u32::try_from(apic).unwrap_or(u32::MAX), Ordering::Release);
    if let Err(error) = processor.spawn(Box::new(move |_| run(tsc_hz, pes)), sender, tsc_hz) {
        output::arguments(format_args!(
            "HOST CORE fallback: its loop was not taken ({error}); PE 0 serves the host and pumps the GPUs\n"
        ));
        return;
    }
    let checked = CHANNEL.self_check(host::rdtsc, tsc_hz / 1000 * PING_MILLIS, || {
        crate::native_mmio::shootdown::service();
        core::hint::spin_loop();
    });
    match checked {
        Ok(ticks) => output::arguments(format_args!(
            "HOST CORE cpu={apic:#x} slot={slot} serving=service-turns,gpu-pump ping_us={} pes={pes}; PE 0 keeps posted GPU calls, the interrupt window and its fallbacks\n",
            u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1)),
        )),
        Err(why) => output::arguments(format_args!(
            "HOST CORE fallback: {why} ({PING_MILLIS} ms) cpu={apic:#x}; PE 0 serves the host and pumps the GPUs\n"
        )),
    }
}

/// The host core's loop, for the rest of the run.
fn run(tsc_hz: u64, pes: usize) -> ! {
    PROCESSOR.store(host::processor(), Ordering::Release);
    // No PE's guest waits on this core: a turn never ends for guest work.
    let watch = GuestWatch::new(None, pes, 0, None);
    let micros = (tsc_hz / 1_000_000).max(1);
    let service_ticks = micros * SERVICE_MICROS;
    let fallback_ticks = micros * PAUSE_MICROS;
    let mut served = host::rdtsc();
    loop {
        crate::native_mmio::shootdown::service();
        let mut pumped = false;
        let turn = CHANNEL.turn(host::fresh_counter());
        match turn {
            Turn::Serve => {
                let now = host::rdtsc();
                if now.wrapping_sub(served) >= service_ticks {
                    served = now;
                    service::serve(false, false, &watch);
                    // The translation pack's background preload, a
                    // bounded step: here PE 0 leaves it to this core.
                    super::translations::background();
                    TURNS.fetch_add(1, Ordering::Relaxed);
                }
                if gpu::pump_host_core() {
                    PUMPS.fetch_add(1, Ordering::Relaxed);
                    pumped = true;
                }
            }
            Turn::Idle => {}
            Turn::Leave => break,
        }
        let wakeable = matches!(turn, Turn::Serve);
        let wait_us = if pumped {
            PAUSE_MICROS
        } else {
            let elapsed = host::rdtsc().wrapping_sub(served);
            let left_us = service_ticks.saturating_sub(elapsed) / micros;
            left_us.clamp(PAUSE_MICROS, SERVICE_MICROS)
        };
        pause(wait_us, fallback_ticks, wakeable);
    }
    // Stopped: it serves nothing more, and answers shootdowns for good.
    loop {
        crate::native_mmio::shootdown::service();
        pause(1000, fallback_ticks, false);
    }
}

fn pause(wait_us: u64, fallback_ticks: u64, wakeable: bool) {
    // Halted, the host core uses no window translation: shootdowns count it
    // as acknowledged until it wakes, and it flushes first then.
    let _idle = crate::native_mmio::shootdown::idle();
    if wakeable {
        SLEEPING.store(true, Ordering::Release);
    }
    let slept = host::try_sleep_for(wait_us);
    if wakeable {
        SLEEPING.store(false, Ordering::Release);
    }
    if !slept {
        let start = host::rdtsc();
        while host::rdtsc().wrapping_sub(start) < fallback_ticks {
            core::hint::spin_loop();
        }
    }
}

/// The run's end, before the service is taken back: the host core stops,
/// or is given up after [`STOP_MILLIS`]; nothing has it serve after this.
pub(super) fn stop(tsc_hz: u64) {
    let state = CHANNEL.state();
    if matches!(state, State::Off | State::Stopped) {
        return;
    }
    let acknowledged = CHANNEL.stop(host::rdtsc, tsc_hz / 1000 * STOP_MILLIS, || {
        crate::native_mmio::shootdown::service();
        core::hint::spin_loop();
    });
    output::arguments(format_args!(
        "HOST CORE stop: {} (was {})\n",
        if acknowledged {
            "acknowledged"
        } else {
            "no answer, given up"
        },
        state.name(),
    ));
}

/// The beat's part of the services line: each taker's time served since
/// the last report and PE 0's share of it, then, with a host core, its
/// state and passes.
pub(super) fn report(tsc_hz: u64) -> String {
    let (ticks, total) = SHARES.take();
    let us = |ticks: u64| u128::from(ticks) * 1_000_000 / u128::from(tsc_hz.max(1));
    let mut line = format!(
        " served_us waiting={} boot={} host_core={} pe0_share={}%",
        us(ticks[Taker::Waiting as usize]),
        us(ticks[Taker::Boot as usize]),
        us(ticks[Taker::HostCore as usize]),
        percent(ticks[Taker::Boot as usize], total),
    );
    let state = CHANNEL.state();
    if state != State::Off {
        line.push_str(&format!(
            " host_core_state={} host_core_turns={} host_core_pumps={}",
            state.name(),
            TURNS.swap(0, Ordering::Relaxed),
            PUMPS.swap(0, Ordering::Relaxed),
        ));
    }
    line
}

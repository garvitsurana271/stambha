//! Perceptual 16-stop stepping for native Linux DRM panel backlights
//! (`BACKLIGHT_RAW`, such as `amdgpu_bl0` on eDP OLED panels or
//! `intel_backlight`), driven by ACPI brightness key notifications.

/// `ACPI_VIDEO_NOTIFY_*` codes (matching `stela_drivers::probe::backlight`).
pub const NOTIFY_CYCLE: u32 = 0x85;
pub const NOTIFY_INC: u32 = 0x86;
pub const NOTIFY_DEC: u32 = 0x87;
pub const NOTIFY_ZERO: u32 = 0x88;
pub const NOTIFY_OFF: u32 = 0x89;

/// 16 perceptual stops in per-mille of `max_brightness` (1.5% ..= 100%).
/// Fine steps at the bottom keep OLED panels controllable indoors without
/// blanking the panel on `NOTIFY_DEC`, while still reaching 100% in 15 taps.
const STOPS_PER_MILLE: [u32; 16] = [
    15, 30, 50, 80, 120, 170, 230, 300, 380, 470, 560, 660, 760, 860, 930, 1000,
];

fn stop_level(max: u32, per_mille: u32) -> u32 {
    if max == 0 {
        return 0;
    }
    let scaled = ((u64::from(max) * u64::from(per_mille) + 500) / 1000) as u32;
    scaled.clamp(1, max)
}

/// The next raw backlight level for `event` given `current` and `max`.
pub fn step(current: u32, max: u32, event: u32) -> u32 {
    if max == 0 {
        return 0;
    }
    let current = current.min(max);
    let levels = STOPS_PER_MILLE.map(|pm| stop_level(max, pm));
    let min = levels[0];
    let above = || levels.iter().copied().find(|&lvl| lvl > current);
    let below = || levels.iter().copied().rev().find(|&lvl| lvl < current);
    match event {
        NOTIFY_INC => above().unwrap_or(max),
        NOTIFY_DEC => below().unwrap_or(min),
        NOTIFY_CYCLE => above().unwrap_or(min),
        NOTIFY_ZERO | NOTIFY_OFF => 0,
        _ => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oled_496k_steps_monotonically_down_and_up() {
        let max = 496_000;
        let mut cur = max;
        let mut down = alloc::vec![cur];
        for _ in 0..20 {
            let next = step(cur, max, NOTIFY_DEC);
            if next == cur {
                break;
            }
            assert!(next < cur);
            cur = next;
            down.push(cur);
        }
        assert_eq!(down.len(), 16);
        assert_eq!(*down.last().unwrap(), 7_440);
        // Further DEC stays at the non-zero floor.
        assert_eq!(step(cur, max, NOTIFY_DEC), 7_440);

        let mut up = alloc::vec![cur];
        for _ in 0..20 {
            let next = step(cur, max, NOTIFY_INC);
            if next == cur {
                break;
            }
            assert!(next > cur);
            cur = next;
            up.push(cur);
        }
        assert_eq!(up.len(), 16);
        assert_eq!(*up.last().unwrap(), max);
    }

    #[test]
    fn pwm_255_and_cycle_and_off_work() {
        assert_eq!(step(255, 255, NOTIFY_CYCLE), 4);
        assert_eq!(step(100, 255, NOTIFY_ZERO), 0);
        assert_eq!(step(100, 255, NOTIFY_OFF), 0);
        assert_eq!(step(0, 255, NOTIFY_INC), 4);
        assert_eq!(step(0, 0, NOTIFY_INC), 0);
    }
}

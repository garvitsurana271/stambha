//! DRM character-device numbering over the shared Linux file service, plus
//! native `BACKLIGHT_RAW` panel brightness control.
use stela_linux::{client, owner::Errno};

/// Open DRM's character device `minor`, for a descriptor or negative errno.
///
/// # Safety
/// Entered in a Linux owner on a task; the open operation may sleep.
pub unsafe fn open(minor: u32) -> Errno {
    const DRM_MAJOR: u32 = 226;
    const MINOR_BITS: u32 = 20;
    const READ_WRITE: u32 = 2;
    // SAFETY: the caller supplies the entered owner and task.
    unsafe { client::open(DRM_MAJOR << MINOR_BITS | minor, READ_WRITE) }
}

#[cfg(feature = "linux-drm")]
unsafe extern "C" {
    fn stela_linux_backlight_info(current: *mut u32, max: *mut u32) -> core::ffi::c_int;
    fn stela_linux_backlight_set(level: u32) -> core::ffi::c_int;
}

/// Reads `(current, max)` brightness from the first registered Linux
/// `BACKLIGHT_RAW` device (e.g. `amdgpu_bl0`), or a negative errno.
///
/// # Safety
/// Entered in a Linux owner on a task; `get_brightness` may sleep.
#[cfg(feature = "linux-drm")]
pub unsafe fn backlight_info() -> Result<(u32, u32), i32> {
    let (mut current, mut max) = (0u32, 0u32);
    // SAFETY: the caller supplies the entered owner and task; pointers are valid.
    let rc = unsafe { stela_linux_backlight_info(&mut current, &mut max) };
    if rc == 0 { Ok((current, max)) } else { Err(rc) }
}

/// Sets the first registered Linux `BACKLIGHT_RAW` device to `level`.
///
/// # Safety
/// Entered in a Linux owner on a task; `update_status` may sleep.
#[cfg(feature = "linux-drm")]
pub unsafe fn backlight_set(level: u32) -> Result<(), i32> {
    // SAFETY: the caller supplies the entered owner and task.
    let rc = unsafe { stela_linux_backlight_set(level) };
    if rc == 0 { Ok(()) } else { Err(rc) }
}

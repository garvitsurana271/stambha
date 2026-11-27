//! The request codes the GPU reports count a service's host calls under: an
//! ioctl's own code, and a small code of its own for each other host call
//! (a map, a page fault, a file open), below every ioctl's, which carries
//! its argument's size and direction. [`Request`] prints either, so a long
//! map or fault reads as one rather than as request zero.

/// A host call that is not an ioctl, by its code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum HostCall {
    Open = 1,
    Close = 2,
    Duplicate = 3,
    Device = 4,
    Map = 5,
    Unmap = 6,
    Fault = 7,
    Thread = 8,
    Wake = 9,
    Export = 10,
    Shutdown = 11,
    Seek = 12,
    BacklightInfo = 13,
    BacklightSet = 14,
}

impl HostCall {
    const ALL: [Self; 14] = [
        Self::Open,
        Self::Close,
        Self::Duplicate,
        Self::Device,
        Self::Map,
        Self::Unmap,
        Self::Fault,
        Self::Thread,
        Self::Wake,
        Self::Export,
        Self::Shutdown,
        Self::Seek,
        Self::BacklightInfo,
        Self::BacklightSet,
    ];

    pub const fn code(self) -> u32 {
        self as u32
    }

    fn name(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Close => "close",
            Self::Duplicate => "dup",
            Self::Device => "device",
            Self::Map => "map",
            Self::Unmap => "unmap",
            Self::Fault => "fault",
            Self::Thread => "thread",
            Self::Wake => "wake",
            Self::Export => "export",
            Self::Shutdown => "shutdown",
            Self::Seek => "seek",
            Self::BacklightInfo => "backlight-info",
            Self::BacklightSet => "backlight-set",
        }
    }
}

/// A request code as the reports print it: an ioctl's in hex, another host
/// call's by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request(pub u32);

impl core::fmt::Display for Request {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match HostCall::ALL.iter().find(|call| call.code() == self.0) {
            Some(call) => f.write_str(call.name()),
            None => write!(f, "{:#x}", self.0),
        }
    }
}

/// `DRM_IOCTL_AMDGPU_INFO`: `DRM_IOW(DRM_COMMAND_BASE + 0x05, struct
/// drm_amdgpu_info)`, 32 bytes, whose code no other driver's ioctl has.
pub const AMDGPU_INFO: u32 = 0x4020_6445;
/// `AMDGPU_INFO_HW_IP_COUNT`: how many engines of a hardware type the GPU
/// has.
pub const AMDGPU_INFO_HW_IP_COUNT: u32 = 0x03;
const EINVAL: i64 = -22;

/// Whether a DRM call's error `result` is its driver's answer to a probe,
/// which is no refusal: amdgpu answers `AMDGPU_INFO_HW_IP_COUNT` for a
/// hardware engine type the GPU lacks with EINVAL (`amdgpu_info_ioctl`),
/// and RADV asks about every type on every GPU. `query` is an
/// `AMDGPU_INFO` call's query, where it was kept.
pub fn probe_answer(request: u32, query: Option<u32>, result: i64) -> bool {
    request == AMDGPU_INFO && query == Some(AMDGPU_INFO_HW_IP_COUNT) && result == EINVAL
}

#[cfg(test)]
mod tests {
    use super::{AMDGPU_INFO, AMDGPU_INFO_HW_IP_COUNT, HostCall, Request, probe_answer};
    use alloc::format;

    #[test]
    fn an_engine_count_for_an_engine_the_gpu_lacks_is_an_answer() {
        // igpu2's four lines: RADV's counts of UVD, VCE, UVD_ENC and VPE
        // engines, which a Raphael iGPU has none of.
        assert!(probe_answer(
            AMDGPU_INFO,
            Some(AMDGPU_INFO_HW_IP_COUNT),
            -22
        ));
        // Any other query, error or call stays a refusal, as does one whose
        // query was not kept.
        assert!(!probe_answer(
            AMDGPU_INFO,
            Some(AMDGPU_INFO_HW_IP_COUNT),
            -14
        ));
        assert!(!probe_answer(AMDGPU_INFO, Some(0x02), -22));
        assert!(!probe_answer(AMDGPU_INFO, None, -22));
        // DRM_IOCTL_NOUVEAU_GEM_NEW.
        assert!(!probe_answer(
            0xc030_6480,
            Some(AMDGPU_INFO_HW_IP_COUNT),
            -22
        ));
    }

    #[test]
    fn host_calls_print_by_name_and_ioctls_in_hex() {
        assert_eq!(format!("{}", Request(HostCall::Map.code())), "map");
        assert_eq!(format!("{}", Request(HostCall::Fault.code())), "fault");
        // DRM_IOCTL_NOUVEAU_GEM_NEW.
        assert_eq!(format!("{}", Request(0xc030_6480)), "0xc0306480");
        assert_eq!(format!("{}", Request(0)), "0x0");
        // Every ioctl code carries its argument's size, at bit 16: none is
        // as small as a host call's.
        for call in HostCall::ALL {
            assert!(call.code() < 1 << 16);
            assert_eq!(format!("{}", Request(call.code())), call.name());
        }
    }
}

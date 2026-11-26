//! Linux's command line for the GPU drivers: the words that set built-in
//! modules' parameters before any of them registers ([`crate::stack::start_kernel`]).
//! Linux refuses a word no built-in module declares, and that refusal fails
//! the whole start, so each word is checked against the parameters the
//! image's objects register, and one they do not is left out by name.
use alloc::{format, string::String, vec::Vec};

/// Every `module.parameter` the image registers: the name of each module
/// parameter its captured units declare, read from those objects (the ones
/// the image links) by the build (`build/image.rs`).
pub const REGISTERED: &[&str] = include!(concat!(env!("OUT_DIR"), "/parameters.rs"));

/// TTM's limit for an integrated GPU whose share of RAM is `share` pages,
/// which Linux also sees as all its RAM (the page catalog's limit).
///
/// The limit is twice the share. amdgpu sizes its GTT by TTM's limit and
/// caps an APU's at the RAM Linux sees, so its GTT is the share; with the
/// default, half the RAM, it was half the share. And TTM swaps buffers out
/// to shmem whenever the pages it counts, with those a buffer is about to
/// take, pass its limit (`ttm_tt_populate`). Here there is no swap, and
/// shmem would be RAM of the same share, so that path must never run. The
/// pages TTM holds are at most the share, as the page catalog refuses more,
/// and a buffer's pages at most its GTT's size, the share again, so no
/// count passes twice the share: a buffer the share cannot hold fails its
/// allocation from the catalog instead.
pub fn page_limit(share: usize) -> String {
    format!("ttm.pages_limit={}", share.saturating_mul(2))
}

/// TTM's limit where no share is planned: the bound on Linux's pages,
/// `pages` (the page catalog's limit, what the heap holds past its own
/// needs). A discrete GPU's GTT is TTM's limit (amdgpu caps only an APU's),
/// so it holds the pages the heap can give. TTM's count passes it only
/// where Linux's pages would pass the catalog's limit too; its swap to
/// shmem is then refused, and the allocation fails as it would at the
/// catalog.
pub fn bound(pages: usize) -> String {
    format!("ttm.pages_limit={pages}")
}

/// TTM's retained page pool, 128 MiB of 4 KiB pages per NUMA node. TTM
/// defaults to half of the node's RAM, which on this 16 GiB host keeps nearly
/// 4 GiB of freed driver pages in the pool; they never return to Stela's heap,
/// so an Intel desktop eventually fails `execbuf` with ENOMEM while the page
/// limit still shows room. A bounded pool returns those pages and keeps the
/// allocation retries short.
pub const PAGE_POOL_PAGES: usize = 32 * 1024;

/// The command-line word that bounds TTM's page pool.
pub fn page_pool() -> String {
    format!("ttm.page_pool_size={PAGE_POOL_PAGES}")
}

/// The firmware file the Intel display code of `driver` (`xe` or `i915`,
/// each of which builds it as its own module's) asks for the video BIOS
/// table before it looks anywhere else (`intel_bios.c`).
pub fn video_bios_table(driver: &str, file: &str) -> String {
    format!("{driver}.vbt_firmware={file}")
}

/// An empty path for the HuC image of Intel `driver` (`xe` or `i915`),
/// which turns its media controller off (`xe_uc_fw.c`, `intel_uc_fw.c`).
pub fn without_huc(driver: &str) -> String {
    format!("{driver}.huc_firmware_path=")
}

/// An empty path for the GSC image of Intel `driver`, which turns its
/// security controller off.
pub fn without_gsc(driver: &str) -> String {
    format!("{driver}.gsc_firmware_path=")
}

/// Turns off panel self refresh. Ice Lake's eDP panel blanks when PSR is
/// left on: the GUI logs appear, then the panel goes black until a modeset.
pub fn without_psr(driver: &str) -> String {
    format!("{driver}.enable_psr=0")
}

/// Turns off panel replay, the PSR successor, for the same blanking reason.
pub fn without_panel_replay(driver: &str) -> String {
    format!("{driver}.enable_panel_replay=0")
}

/// Turns off framebuffer compression for the same blanking reason.
pub fn without_fbc(driver: &str) -> String {
    format!("{driver}.enable_fbc=0")
}

/// The masks amdgpu reads once for every GPU it drives, whose bits are the
/// link speeds and widths it may use ([`crate::amdgpu::link`]).
const LINK_MASKS: [&str; 2] = ["amdgpu.pcie_gen_cap", "amdgpu.pcie_lane_cap"];

/// Adds `word` to `words` unless it is there already. One of amdgpu's link
/// masks that another GPU set differently keeps the bits both set, the
/// narrower link of the two: Linux's last word would give one GPU a link
/// faster than its slot's.
pub fn add(words: &mut Vec<String>, word: &str) {
    if words.iter().any(|seen| seen == word) {
        return;
    }
    let mask = |word: &str| {
        let (name, value) = word.split_once('=')?;
        let value = u32::from_str_radix(value.strip_prefix("0x")?, 16).ok()?;
        LINK_MASKS
            .contains(&name)
            .then_some((String::from(name), value))
    };
    if let Some((name, value)) = mask(word)
        && let Some((seen, held)) = words.iter_mut().find_map(|seen| {
            mask(seen)
                .filter(|(other, _)| *other == name)
                .map(|(_, held)| (seen, held))
        })
    {
        *seen = format!("{name}={:#x}", held & value);
        return;
    }
    words.push(String::from(word));
}

/// Whether a parameter the image registers takes `word`. Linux matches
/// names with `-` and `_` alike (`parameq`).
pub fn registered(word: &str) -> bool {
    let name = word.split_once('=').map_or(word, |(name, _)| name);
    let same = |a: u8, b: u8| a == b || matches!((a, b), (b'-', b'_') | (b'_', b'-'));
    REGISTERED.iter().any(|known| {
        known.len() == name.len() && known.bytes().zip(name.bytes()).all(|(a, b)| same(a, b))
    })
}

/// The command line of `words`, in order, and the words left out of it
/// because no parameter the image registers takes them.
pub fn compose(words: impl IntoIterator<Item = String>) -> (String, Vec<String>) {
    let (kept, left_out): (Vec<String>, Vec<String>) =
        words.into_iter().partition(|word| registered(word));
    (kept.join(" "), left_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Every word the boot can put on the command line names a parameter
    /// the built objects register, so none is refused or left out.
    #[test]
    fn every_word_the_boot_builds_is_registered() {
        let mut words = vec![page_limit(655_360), bound(224_256), page_pool()];
        // Only an image with an Intel driver holds its parameters: its own
        // (i915's in `i915_params.c`, xe's in `xe_module.c`) and those of the
        // display code it builds.
        for (driver, built) in [
            ("xe", cfg!(feature = "xe-port")),
            ("i915", cfg!(feature = "i915-port")),
        ] {
            if built {
                words.extend([
                    video_bios_table(driver, "intel/vbt.bin"),
                    without_psr(driver),
                    without_panel_replay(driver),
                    without_fbc(driver),
                    without_huc(driver),
                    without_gsc(driver),
                ]);
            }
        }
        // amdgpu's link masks for a discrete GPU (`amdgpu_drv.c`).
        #[cfg(feature = "amdgpu-port")]
        words.extend(
            crate::amdgpu::link::Link {
                generation: 4,
                width: 16,
            }
            .parameters()
            .split_whitespace()
            .map(String::from),
        );
        let (line, left_out) = compose(words.clone());
        assert!(
            left_out.is_empty(),
            "not registered: {left_out:?} of {REGISTERED:?}"
        );
        assert_eq!(line, words.join(" "));
    }

    #[test]
    fn an_unknown_word_is_left_out_by_name() {
        let (line, left_out) = compose([
            String::from("ttm.no_such_parameter=1"),
            page_limit(8),
            String::from("bare"),
        ]);
        assert_eq!(line, "ttm.pages_limit=16");
        assert_eq!(left_out, ["ttm.no_such_parameter=1", "bare"]);
        assert!(registered("ttm.pages-limit=1"));
    }

    /// A word is added once; two GPUs' link masks keep the narrower link,
    /// whichever comes first.
    #[test]
    fn two_gpus_link_masks_keep_the_narrower_link() {
        let mut words = Vec::new();
        for word in [
            "ttm.pages_limit=8",
            "amdgpu.pcie_gen_cap=0xf000f",
            "amdgpu.pcie_lane_cap=0x3f003f",
            "ttm.pages_limit=8",
            "amdgpu.pcie_gen_cap=0x70007",
            "amdgpu.pcie_lane_cap=0x3f003f",
            "amdgpu.pcie_lane_cap=0xf000f",
            "amdgpu.pcie_gen_cap=0xf000f",
        ] {
            add(&mut words, word);
        }
        assert_eq!(
            words,
            [
                "ttm.pages_limit=8",
                "amdgpu.pcie_gen_cap=0x70007",
                "amdgpu.pcie_lane_cap=0xf000f"
            ]
        );
        // Another word keeps Linux's own rule: added as it is.
        add(&mut words, "ttm.pages_limit=16");
        assert_eq!(words.last().map(String::as_str), Some("ttm.pages_limit=16"));
    }

    /// A share's limit is twice it; a bound is itself.
    #[test]
    fn a_bound_is_ttms_limit_as_it_is() {
        assert_eq!(page_limit(655_360), "ttm.pages_limit=1310720");
        assert_eq!(bound(224_256), "ttm.pages_limit=224256");
        assert_eq!(page_pool(), "ttm.page_pool_size=32768");
    }
}

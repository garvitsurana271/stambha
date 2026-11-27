//! The background preload of a translation pack read on demand.
//!
//! A pack read on demand keeps only its segments' headers and indexes in
//! memory (and the first bytes of its oldest segment the loader read ahead):
//! a lookup of a page whose record lies only in the file is answered
//! [`Looked::Awaited`], its block compiles, and the reader reads the record
//! for a later fetch. On a USB stick that answers one command at a time a
//! record's read waits behind every read before it (60 to 570 ms a record
//! on the SanDisk stick of 2026-11-23, whose boots found 4 thousand of 2.7
//! million awaited lookups served), so the pack's records arrived after
//! their blocks had compiled.
//!
//! Here the loader sets memory aside for the rest of the pack ([`plan`]),
//! and after the guest starts the records left in the file are read into it
//! in large sequential reads ([`BulkReader`]), the records the boot that
//! merged the pack used first, first. A lookup whose record's pieces lie in
//! what was read decodes it from memory ([`lookup`], [`held_record`]),
//! checked by its own trailer as a record read from the file is. A key no
//! segment holds is answered from the indexes in memory and never read.
//!
//! The bulk reads never queue ahead of a lookup's read: one is in flight at
//! a time, so a record's read, started at once, waits behind that one chunk
//! at most, and the next chunk is started after it, behind it. Record reads
//! are few while the preload runs ([`RECORD_READS`]): each costs a command
//! as a chunk does, and a record inside the chunk in flight or the next
//! ones ([`SOON`]) waits for them instead of reading again ([`Asked`]).
use alloc::{collections::VecDeque, format, string::String, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use stela_drivers::block::{BlockDevice, Command};
use stela_engine::machine::Looked;
use stela_engine::translations::pack::{
    DecodeScratch, DecodedRecord, MAX_SEGMENTS, Pack, Store, Stored, Wanted,
};
use stela_engine::translations::{Digest, StoredRecord};
use stela_formats::journal;
use stela_formats::payload::pieces::Extent;

/// The most record reads a lookup asked for that are in flight while a
/// preload runs. On a stick that runs one command at a time each waits for
/// those before it, and a chunk of the preload brings sixty records in the
/// time one such read takes: more of them would only hold the preload, which
/// serves the rest of a launch.
pub const RECORD_READS: usize = 2;
/// A record that lies within this many chunks past where the preload reads
/// waits for it, reading nothing of its own.
pub const SOON: u64 = 2;

/// A range of the pack file held in memory: its first byte's offset in the
/// file and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub file: u64,
    pub length: u64,
}

/// A segment left in the file, as the loader plans its preload: where it
/// starts in the file, from where in it its records still lie only in the
/// file (`translation_store::first_left`), and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Planned {
    pub file: u64,
    pub from: u64,
    pub length: u64,
}

/// The spans to hold of `segments`, in their order, within `capacity`
/// bytes: each segment from where its records left in the file begin to
/// its end, the last one cut where the capacity ends. A merge lays a
/// segment's records out in the order a boot first used them, so a cut
/// span holds the records used first; those past it are read on demand.
pub fn plan(segments: &[Planned], capacity: u64) -> Vec<Span> {
    let mut left = capacity;
    let mut spans = Vec::new();
    for segment in segments {
        if left == 0 {
            break;
        }
        let length = segment.length.saturating_sub(segment.from).min(left);
        if length == 0 {
            continue;
        }
        spans.push(Span {
            file: segment.file.saturating_add(segment.from),
            length,
        });
        left -= length;
    }
    spans
}

/// The memory a background preload fills: each span's bytes, one after
/// another, and how many of each have been read, which only grows. Bytes
/// below a span's count are written once and never again; only the one
/// [`BulkReader`] writes, above it.
pub struct Bulk {
    base: *mut u8,
    capacity: usize,
    spans: Vec<Held>,
    retired: AtomicBool,
}

struct Held {
    span: Span,
    /// Where its bytes start in the memory.
    at: usize,
    filled: AtomicU64,
}

// SAFETY: the bytes of a span below its `filled` are written before the
// Release store that counts them and never again, and readers read only
// below a count they load with Acquire; above it only the one `BulkReader`
// (`&mut`) writes.
unsafe impl Send for Bulk {}
// SAFETY: as for `Send`.
unsafe impl Sync for Bulk {}

impl Bulk {
    /// The preload of `spans` into the `capacity` bytes at `base`, nothing
    /// read yet: `None` when they do not fit, one is empty or one's end
    /// overflows.
    ///
    /// # Safety
    /// `base..base + capacity` is writable memory that nothing else uses
    /// for as long as the preload lives.
    pub unsafe fn new(base: *mut u8, capacity: usize, spans: &[Span]) -> Option<Self> {
        let mut at = 0usize;
        let mut held = Vec::with_capacity(spans.len());
        for span in spans {
            let length = usize::try_from(span.length).ok()?;
            let end = at.checked_add(length)?;
            span.file.checked_add(span.length)?;
            if end > capacity || length == 0 {
                return None;
            }
            held.push(Held {
                span: *span,
                at,
                filled: AtomicU64::new(0),
            });
            at = end;
        }
        Some(Self {
            base,
            capacity,
            spans: held,
            retired: AtomicBool::new(false),
        })
    }

    /// The `length` bytes of the pack file at `file`, when a span holds
    /// them all and they have been read; `None` once the preload is
    /// retired.
    pub fn bytes(&self, file: u64, length: u64) -> Option<&[u8]> {
        if self.retired() {
            return None;
        }
        let end = file.checked_add(length)?;
        self.spans.iter().find_map(|held| {
            let filled = held.filled.load(Ordering::Acquire);
            let from = file.checked_sub(held.span.file)?;
            (end <= held.span.file + filled).then(|| {
                let at = held.at + from as usize;
                // SAFETY: within the span's bytes read, which were written
                // before `filled` counted them and are never written again.
                unsafe { core::slice::from_raw_parts(self.base.add(at), length as usize) }
            })
        })
    }

    /// The bytes it holds once whole.
    pub fn total(&self) -> u64 {
        self.spans.iter().map(|held| held.span.length).sum()
    }

    /// The bytes read so far.
    pub fn held(&self) -> u64 {
        self.spans
            .iter()
            .map(|held| held.filled.load(Ordering::Acquire))
            .sum()
    }

    /// Whether every span has been read.
    pub fn complete(&self) -> bool {
        self.held() == self.total()
    }

    /// The spans planned.
    pub fn planned(&self) -> Vec<Span> {
        self.spans.iter().map(|held| held.span).collect()
    }

    /// The memory set aside, in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The file's space under the spans may hold other bytes now (a merge
    /// replaced the segments they lie in): nothing is served or read again.
    pub fn retire(&self) {
        self.retired.store(true, Ordering::Release);
    }

    pub fn retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    /// How many bytes the preload reads before it holds the `length` bytes
    /// of the file at `file`, from where it reads next: `None` when no span
    /// holds them whole.
    fn ahead(&self, file: u64, length: u64) -> Option<u64> {
        let end = file.checked_add(length)?;
        let mut before = 0u64;
        for held in &self.spans {
            let filled = held.filled.load(Ordering::Acquire);
            let (start, stop) = (held.span.file, held.span.file + held.span.length);
            if start <= file && end <= stop {
                return Some(before + end.saturating_sub(start + filled));
            }
            before += held.span.length - filled;
        }
        None
    }

    /// The next bytes to read, at most `chunk` of them: the span, where in
    /// the file and how many.
    fn next(&self, chunk: u64) -> Option<(usize, u64, u64)> {
        self.spans.iter().enumerate().find_map(|(index, held)| {
            let filled = held.filled.load(Ordering::Acquire);
            let left = held.span.length - filled;
            (left != 0).then(|| (index, held.span.file + filled, left.min(chunk.max(1))))
        })
    }

    /// Count `data`, read at span `span`'s end of what it holds.
    ///
    /// # Safety
    /// Only the one [`BulkReader`] calls it, and `data` fits the span.
    unsafe fn land(&self, span: usize, data: &[u8]) {
        let held = &self.spans[span];
        let filled = held.filled.load(Ordering::Acquire);
        debug_assert!(filled + data.len() as u64 <= held.span.length);
        // SAFETY: past what was read, inside the span's memory, which only
        // this reader writes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.base.add(held.at + filled as usize),
                data.len(),
            );
        }
        held.filled
            .store(filled + data.len() as u64, Ordering::Release);
    }
}

/// `key`'s pieces in `segments`, as a store's reader wants them
/// (`Store::take_wanted`): `None` when no segment's index holds it.
pub fn wanted(segments: &[Pack<'_>], key: &Digest) -> Option<Wanted> {
    let mut pieces = [None; MAX_SEGMENTS];
    for (piece, pack) in pieces.iter_mut().zip(segments) {
        *piece = pack.locate(key);
    }
    pieces
        .iter()
        .any(Option::is_some)
        .then_some(Wanted { key: *key, pieces })
}

/// The bytes of each piece of `wanted` that lies in a segment left in the
/// file, from `bulk`, the segments' file offsets being `offsets` (`None` for
/// one held whole): `None` unless it holds every such piece.
pub fn held<'b>(
    bulk: &'b Bulk,
    offsets: &[Option<u64>],
    wanted: &Wanted,
) -> Option<[Option<&'b [u8]>; MAX_SEGMENTS]> {
    let mut read = [None; MAX_SEGMENTS];
    let mut any = false;
    for ((slot, piece), offset) in read.iter_mut().zip(&wanted.pieces).zip(offsets) {
        let (Some((at, bytes)), Some(base)) = (*piece, *offset) else {
            continue;
        };
        *slot = Some(bulk.bytes(base.checked_add(at)?, bytes)?);
        any = true;
    }
    any.then_some(read)
}

/// `key`'s record as `store` reads it from what `bulk` holds, unless a piece
/// left in the file is not held yet: what [`DecodedRecord::decode`] decodes,
/// then [`Store::finish_read`] takes, as for a record read from the file.
pub fn held_record<'a>(
    store: &Store<'a>,
    offsets: &[Option<u64>],
    bulk: &'a Bulk,
    key: &Digest,
) -> Option<(Wanted, Stored<'a>)> {
    let wanted = wanted(store.segments(), key)?;
    let read = held(bulk, offsets, &wanted)?;
    let stored = store.read_stored(&wanted, &read)?;
    Some((wanted, stored))
}

/// A lookup of `key` in `store`, its segments left in the file at
/// `offsets`, with what `bulk` holds of them: as the boot's store looks up
/// (`translations::Shared::lookup`), on one thread. A record in memory, a
/// segment's or the preload's, is decoded and found; one only in the file
/// is asked for; a key no index holds is absent and never read.
pub fn lookup<'a>(
    store: &mut Store<'a>,
    offsets: &[Option<u64>],
    bulk: Option<&'a Bulk>,
    key: &Digest,
) -> Looked {
    if let Some(record) = store.cached_record(key) {
        return Looked::Found(record);
    }
    let translator = *store.translator();
    if let Some(stored) = store.stored(key) {
        let mut scratch = store.take_decode_scratch(stored);
        let decoded = DecodedRecord::decode(stored, &translator, key, &mut scratch);
        drop(store.finish_decode(key, stored, &decoded, &mut scratch));
        return found(decoded.ok().map(DecodedRecord::into_record));
    }
    if let Some((wanted, stored)) = bulk.and_then(|bulk| held_record(store, offsets, bulk, key)) {
        let decoded =
            DecodedRecord::decode(stored, &translator, key, &mut DecodeScratch::default());
        drop(store.finish_read(key, wanted.bytes(), Some(&decoded)));
        return found(decoded.ok().map(DecodedRecord::into_record));
    }
    if store.want(key) {
        return Looked::Awaited;
    }
    store.looked_up(key, false, false);
    Looked::Absent
}

fn found(record: Option<Arc<StoredRecord>>) -> Looked {
    record.map_or(Looked::Absent, Looked::Found)
}

/// What the reader does with a record a lookup asked for while a preload
/// runs: decode it from the bytes held, wait for the preload's read in
/// flight or its next [`SOON`] chunks that hold it, or read it.
pub enum Asked<'b> {
    Held([Option<&'b [u8]>; MAX_SEGMENTS]),
    Landing,
    Read,
}

/// [`Asked`] for `wanted`.
pub fn asked<'b>(
    bulk: &'b Bulk,
    reader: &BulkReader<'_>,
    offsets: &[Option<u64>],
    wanted: &Wanted,
) -> Asked<'b> {
    if let Some(read) = held(bulk, offsets, wanted) {
        return Asked::Held(read);
    }
    let lands = wanted
        .pieces
        .iter()
        .zip(offsets)
        .filter_map(|(piece, offset)| Some(((*piece)?, (*offset)?)))
        .all(|((at, bytes), base)| reader.soon(base + at, bytes));
    match lands && !reader.done() && !bulk.retired() {
        true => Asked::Landing,
        false => Asked::Read,
    }
}

/// One read of `bytes` bytes of the pack file at `at` in flight: the
/// blocks' buffer, where the bytes start in it, the device chunks still
/// waiting for queue room (`(lba, bytes, offset)`), and the device reads
/// in flight (`(tag, offset)`).
pub struct FileRead {
    buffer: Vec<u8>,
    skip: usize,
    bytes: usize,
    pending: alloc::collections::VecDeque<(u64, usize, usize)>,
    reads: Vec<(u32, usize)>,
    failed: bool,
}

impl FileRead {
    /// Start the read of the file whose device extents are `extents`:
    /// `None` when the range is outside the file or the device refused a
    /// command. Each extent is split to the device's read transfer limit so
    /// a queued controller whose `room` reserves one `max_transfer` command
    /// (such as NVMe's `BOUNCE_BYTES` bounce pool) never sees an oversized
    /// read, and chunks beyond the device's current queue room wait in
    /// `pending` until [`Self::poll`] submits them.
    pub fn start(
        device: &mut dyn BlockDevice,
        extents: &[Extent],
        at: u64,
        bytes: u64,
    ) -> Option<Self> {
        let identity = device.identity();
        let block = u64::from(identity.block_size).max(1);
        let chunk = match identity.features.transfer_limit(true) {
            0 => u64::MAX,
            limit => (limit as u64 / block * block).max(block),
        };
        let start = at / block * block;
        let end = at.checked_add(bytes)?.next_multiple_of(block);
        let ranges = journal::device_ranges(extents, block, start, end - start)?;
        let mut pending = alloc::collections::VecDeque::new();
        for (lba, length, from) in ranges {
            let mut done = 0u64;
            while done < length {
                let piece = (length - done).min(chunk);
                pending.push_back((lba + done / block, piece as usize, from + done as usize));
                done += piece;
            }
        }
        let mut read = Self {
            buffer: vec![0; (end - start) as usize],
            skip: (at - start) as usize,
            bytes: bytes as usize,
            pending,
            reads: Vec::new(),
            failed: false,
        };
        read.submit(device);
        if read.failed && read.reads.is_empty() {
            return None;
        }
        Some(read)
    }

    /// Submit waiting chunks while the device has queue room; returns whether
    /// any chunk was submitted.
    fn submit(&mut self, device: &mut dyn BlockDevice) -> bool {
        let mut started = false;
        while !self.failed && device.room() {
            let Some((lba, bytes, from)) = self.pending.pop_front() else {
                break;
            };
            match device.start_more(Command::Read { lba, bytes }) {
                Ok(tag) => {
                    self.reads.push((tag, from));
                    started = true;
                }
                Err(_) => {
                    self.failed = true;
                    self.pending.clear();
                    break;
                }
            }
        }
        started
    }

    /// Take the device reads that ended and submit any waiting chunks as
    /// queue room opens: whether every chunk has ended.
    pub fn poll(&mut self, device: &mut dyn BlockDevice) -> bool {
        let (buffer, failed) = (&mut self.buffer, &mut self.failed);
        self.reads.retain(|&(tag, from)| match device.finish(tag) {
            None => true,
            Some(Ok(Some(data))) => {
                match buffer.get_mut(from..from + data.len()) {
                    Some(into) => into.copy_from_slice(&data),
                    None => *failed = true,
                }
                false
            }
            Some(_) => {
                *failed = true;
                false
            }
        });
        if self.failed {
            self.pending.clear();
        } else if self.submit(device) {
            device.commit();
        }
        self.reads.is_empty() && self.pending.is_empty()
    }

    /// The bytes read, once every device read ended: `None` when one failed.
    pub fn bytes(&self) -> Option<&[u8]> {
        (!self.failed).then(|| &self.buffer[self.skip..self.skip + self.bytes])
    }
}

/// The commands a staged journal write has queued, by the file offset it
/// began at: those waiting for queue room, the tags in flight on the device,
/// and any tags left in flight after an aborted write that must still be
/// collected to free their device queue slots.
#[derive(Default)]
pub struct Queued {
    at: Option<u64>,
    pending: VecDeque<Command>,
    tags: Vec<u32>,
    abandoned: Vec<u32>,
}

/// A staged partition target while the guest runs: each write splits its
/// extents to [`stela_drivers::block::Features::transfer_limit`], paces
/// submissions to [`BlockDevice::room`], and polls until every chunk ends.
pub struct Staged<'a> {
    pub device: &'a mut dyn BlockDevice,
    pub extents: &'a [Extent],
    pub queued: &'a mut Queued,
}

impl Staged<'_> {
    /// Collect any completed tags left in flight by an earlier aborted write
    /// so their device queue slots are returned before reuse.
    fn drain_abandoned(&mut self) {
        self.queued
            .abandoned
            .retain(|&tag| self.device.finish(tag).is_none());
    }

    /// Collect any already-completed tags without blocking, keep any still in
    /// flight in `abandoned` so subsequent turns finish freeing their queue
    /// slots, and reset the active write so a retry at the same offset starts
    /// fresh rather than skipping command setup.
    fn abort(&mut self) {
        for tag in self.queued.tags.drain(..) {
            if self.device.finish(tag).is_none() {
                self.queued.abandoned.push(tag);
            }
        }
        self.queued.at = None;
        self.queued.pending.clear();
    }

    /// Queue `commands` for the write at `at` while the device has queue room,
    /// and take finished results: whether every command finished.
    fn run(
        &mut self,
        at: u64,
        commands: impl FnOnce() -> Result<Vec<Command>, String>,
    ) -> Result<bool, String> {
        self.drain_abandoned();
        if !self.queued.abandoned.is_empty() {
            // Wait for every still-in-flight command from an aborted write to
            // complete so all device queue slots are reclaimed and a retry at
            // the same offset never overlaps an in-flight command.
            return Ok(false);
        }
        if self.queued.at != Some(at) {
            self.queued.at = Some(at);
            self.queued.pending = VecDeque::from(commands()?);
            self.queued.tags.clear();
        }
        let mut index = 0;
        while index < self.queued.tags.len() {
            let tag = self.queued.tags[index];
            match self.device.finish(tag) {
                None => index += 1,
                Some(result) => {
                    self.queued.tags.swap_remove(index);
                    if let Err(error) = result {
                        self.abort();
                        return Err(format!("{error:?}"));
                    }
                }
            }
        }
        let mut started = false;
        while self.device.room() {
            let Some(command) = self.queued.pending.pop_front() else {
                break;
            };
            match self.device.start_more(command) {
                Ok(tag) => {
                    self.queued.tags.push(tag);
                    started = true;
                }
                Err(error) => {
                    if started {
                        self.device.commit();
                    }
                    self.abort();
                    return Err(format!("{error:?}"));
                }
            }
        }
        if started {
            self.device.commit();
        }
        if self.queued.pending.is_empty() && self.queued.tags.is_empty() {
            *self.queued = Queued::default();
            return Ok(true);
        }
        Ok(false)
    }
}

/// The device ranges of `bytes` at file offset `offset`.
fn write_ranges(
    extents: &[Extent],
    block: u64,
    offset: u64,
    bytes: &[u8],
) -> Result<Vec<(u64, u64, usize)>, String> {
    journal::device_ranges(extents, block, offset, bytes.len() as u64).ok_or_else(|| {
        format!(
            "bytes {offset}+{} are not on the file's blocks",
            bytes.len()
        )
    })
}

impl journal::Target for Staged<'_> {
    type Error = String;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<bool, String> {
        let identity = self.device.identity();
        let block = u64::from(identity.block_size).max(1);
        // Queued controllers such as NVMe reserve bounce pages per command up
        // to `transfer_limit(false)` (`BOUNCE_BYTES`): split larger contiguous
        // extents so a 1 MiB journal piece never exhausts the bounce pool.
        let chunk = match identity.features.transfer_limit(false) {
            0 => u64::MAX,
            limit => (limit as u64 / block * block).max(block),
        };
        let extents = self.extents;
        self.run(offset, || {
            let mut commands = Vec::new();
            for (lba, length, from) in write_ranges(extents, block, offset, bytes)? {
                let mut done = 0u64;
                while done < length {
                    let piece = (length - done).min(chunk);
                    let start = from + done as usize;
                    commands.push(Command::Write {
                        lba: lba + done / block,
                        data: bytes[start..start + piece as usize].to_vec(),
                        fua: false,
                    });
                    done += piece;
                }
            }
            Ok(commands)
        })
    }
    /// A device without a write cache is sent no flush, as the block
    /// layer's ([`BlockDevice::flush`]) and the [`Direct`] target's.
    fn flush(&mut self) -> Result<bool, String> {
        if !self.device.identity().features.write_cache {
            return Ok(true);
        }
        self.run(u64::MAX, || Ok(vec![Command::Flush]))
    }
}

/// A synchronous partition target at a stop: each write completes before it
/// returns.
pub struct Direct<'a> {
    pub device: &'a mut dyn BlockDevice,
    pub extents: &'a [Extent],
}

impl journal::Target for Direct<'_> {
    type Error = String;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<bool, String> {
        let block = u64::from(self.device.identity().block_size);
        for (lba, length, from) in write_ranges(self.extents, block, offset, bytes)? {
            self.device
                .write(lba, &bytes[from..from + length as usize])
                .map_err(|error| format!("{error:?}"))?;
        }
        Ok(true)
    }
    fn flush(&mut self) -> Result<bool, String> {
        self.device.flush().map_err(|error| format!("{error:?}"))?;
        Ok(true)
    }
}

/// What a [`BulkReader`] did: the reads it started and the bytes they
/// brought, the counter values of its first read's start and of the end of
/// the last, and why it stopped, once it has.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BulkStats {
    pub reads: u64,
    pub bytes: u64,
    pub started: Option<u64>,
    pub ended: Option<u64>,
    pub stopped: Option<Stopped>,
}

/// Why a preload stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// Every span was read.
    Whole,
    /// A read failed: the rest is read on demand.
    Failed,
    /// A merge replaced the segments: nothing more is read.
    Retired,
}

impl Stopped {
    pub fn name(self) -> &'static str {
        match self {
            Self::Whole => "whole",
            Self::Failed => "failed",
            Self::Retired => "retired",
        }
    }
}

/// The one writer of a [`Bulk`]: reads its spans in order, `chunk` bytes a
/// read, one read at a time.
pub struct BulkReader<'a> {
    bulk: &'a Bulk,
    chunk: u64,
    flight: Option<(usize, u64, FileRead)>,
    pub stats: BulkStats,
}

impl<'a> BulkReader<'a> {
    pub fn new(bulk: &'a Bulk, chunk: u64) -> Self {
        Self {
            bulk,
            chunk: chunk.max(1),
            flight: None,
            stats: BulkStats::default(),
        }
    }

    pub fn bulk(&self) -> &'a Bulk {
        self.bulk
    }

    /// Whether the read in flight holds the `length` bytes of the file at
    /// `file`.
    pub fn landing(&self, file: u64, length: u64) -> bool {
        self.flight.as_ref().is_some_and(|(_, at, read)| {
            *at <= file && file.saturating_add(length) <= *at + read.bytes as u64
        })
    }

    /// Whether the preload holds the `length` bytes of the file at `file`
    /// once its read in flight and its next [`SOON`] chunks have ended.
    pub fn soon(&self, file: u64, length: u64) -> bool {
        let in_flight = self
            .flight
            .as_ref()
            .map_or(0, |(_, _, read)| read.bytes as u64);
        self.bulk
            .ahead(file, length)
            .is_some_and(|ahead| ahead <= in_flight + SOON * self.chunk)
    }

    /// Whether a read is in flight.
    pub fn busy(&self) -> bool {
        self.flight.is_some()
    }

    /// Whether it stopped, every span read or not.
    pub fn done(&self) -> bool {
        self.stats.stopped.is_some()
    }

    /// Take the read in flight once it ended, at counter value `now`:
    /// whether bytes landed. A failed read stops the preload, as a retired
    /// one does.
    pub fn collect(&mut self, device: &mut dyn BlockDevice, now: u64) -> bool {
        let Some((_, _, read)) = self.flight.as_mut() else {
            return false;
        };
        if !read.poll(device) {
            return false;
        }
        let (span, _, read) = self.flight.take().expect("a read in flight");
        if self.bulk.retired() {
            self.stop(Stopped::Retired, now);
            return false;
        }
        let Some(bytes) = read.bytes() else {
            self.stop(Stopped::Failed, now);
            return false;
        };
        // SAFETY: this reader is the bulk's one writer, and the read is the
        // span's next bytes, within it (`Bulk::next`).
        unsafe { self.bulk.land(span, bytes) };
        self.stats.bytes += bytes.len() as u64;
        if self.bulk.complete() {
            self.stop(Stopped::Whole, now);
        }
        true
    }

    /// Start the next read, at counter value `now`, unless one is in
    /// flight or it stopped: whether one started. Call it after starting
    /// the record reads lookups asked for, which then run first, and
    /// [`BlockDevice::commit`] after one did.
    pub fn start(&mut self, device: &mut dyn BlockDevice, extents: &[Extent], now: u64) -> bool {
        if self.flight.is_some() || self.done() || !device.room() {
            return false;
        }
        if self.bulk.retired() {
            self.stop(Stopped::Retired, now);
            return false;
        }
        let Some((span, at, bytes)) = self.bulk.next(self.chunk) else {
            self.stop(Stopped::Whole, now);
            return false;
        };
        let Some(read) = FileRead::start(device, extents, at, bytes) else {
            self.stop(Stopped::Failed, now);
            return false;
        };
        self.stats.started.get_or_insert(now);
        self.stats.reads += 1;
        self.flight = Some((span, at, read));
        true
    }

    fn stop(&mut self, why: Stopped, now: u64) {
        self.stats.stopped.get_or_insert(why);
        self.stats.ended.get_or_insert(now);
    }
}

#[cfg(test)]
mod tests;

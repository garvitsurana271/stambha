//! The background preload over a fake slow USB stick: a Bulk-Only stick
//! that runs one command at a time, in the order they came, each taking a
//! command's cost (5 to 50 ms) and its bytes at 30 MB/s, in simulated time.
//!
//! [`Sim`] steps a store's reads as the boot's reader does
//! (`stela-boot`'s `engine::translations::Reader`, one part): record reads
//! a lookup asked for, served from the preload when it holds them, waiting
//! for it when it soon will, read otherwise, two at a time; one bulk read
//! in flight, started after them. Without a preload
//! it reads as the boot did before it, on a disk whose reads seek: what
//! lookups asked (those that end within a second), the records laid out
//! after each, then the file in layout order.
use super::*;
use alloc::collections::{BTreeMap, VecDeque};
use stela_drivers::block::{BlockError, Features, Finished, Identity, Transport};
use stela_engine::translations::pack::{self, Layout, LayoutOrder, Piece};
use stela_engine::translations::{Digest, Record};

const BLOCK: u32 = 512;
/// Where the segment lies in the file: past a journal's slots, as in a
/// pack file.
const BASE: u64 = 64 << 10;

/// One command the stick ran: when it started and ended, and its first
/// block.
#[derive(Debug, Clone, Copy)]
struct Ran {
    start: u64,
    end: u64,
    lba: u64,
}

/// The fake stick, its clock in microseconds.
struct Stick {
    identity: Identity,
    image: Vec<u8>,
    now: u64,
    /// When the command it runs last ends.
    busy_until: u64,
    /// Ended or running commands not taken yet: when each ends, and its
    /// result.
    pending: BTreeMap<u32, (u64, Finished)>,
    ran: Vec<Ran>,
    next_tag: u32,
    /// Bytes a second, the most and least microseconds a command costs, and
    /// how many bytes of the model each byte of the image stands for.
    rate: u64,
    cost: (u64, u64),
    scale: u64,
    seed: u64,
}

impl Stick {
    fn new(image: Vec<u8>, scale: u64) -> Self {
        Self {
            identity: Identity {
                transport: Transport::Usb,
                location: String::from("fake"),
                model: String::from("slow stick"),
                serial: String::new(),
                blocks: image.len() as u64 / u64::from(BLOCK),
                block_size: BLOCK,
                read_only: false,
                features: Features::default(),
            },
            image,
            now: 0,
            busy_until: 0,
            pending: BTreeMap::new(),
            ran: Vec::new(),
            next_tag: 1,
            rate: 30_000_000,
            cost: (5_000, 50_000),
            scale,
            seed: 0x9e37_79b9_7f4a_7c15,
        }
    }

    /// The next command's cost, spread evenly over the bounds.
    fn command_cost(&mut self) -> u64 {
        self.seed = self
            .seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let (low, high) = self.cost;
        low + (self.seed >> 33) % (high - low + 1)
    }

    fn reads(&self) -> usize {
        self.ran.len()
    }
}

impl BlockDevice for Stick {
    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
        let at = (lba * u64::from(BLOCK)) as usize;
        buffer.copy_from_slice(&self.image[at..at + buffer.len()]);
        Ok(())
    }

    fn write(&mut self, _lba: u64, _data: &[u8]) -> Result<(), BlockError> {
        Err(BlockError::Unsupported("the fake stick is read only"))
    }

    fn depth(&self) -> usize {
        32
    }

    fn room(&self) -> bool {
        self.pending.len() < 32
    }

    /// One at a time, in order: each starts when the one before ends.
    fn start(&mut self, command: Command) -> Result<u32, BlockError> {
        let Command::Read { lba, bytes } = command else {
            return Err(BlockError::Unsupported("reads only"));
        };
        let tag = self.next_tag;
        self.next_tag += 1;
        let start = self.busy_until.max(self.now);
        let end = start + self.command_cost() + bytes as u64 * self.scale * 1_000_000 / self.rate;
        self.busy_until = end;
        let mut data = vec![0; bytes];
        let result = self.read(lba, &mut data).map(|()| Some(data));
        self.pending.insert(tag, (end, result));
        self.ran.push(Ran { start, end, lba });
        Ok(tag)
    }

    fn finish(&mut self, tag: u32) -> Option<Finished> {
        match self.pending.get(&tag) {
            Some(&(end, _)) if end <= self.now => self.pending.remove(&tag).map(|(_, r)| r),
            _ => None,
        }
    }
}

/// Record keys `0..count`.
fn key(index: u32) -> Digest {
    Digest::of(&index.to_le_bytes())
}

/// A segment of `count` valid, empty records of `translator`, laid out in
/// key order, which is the order its boot used them.
fn segment(translator: Digest, count: u32) -> Vec<u8> {
    let records = (0..count)
        .map(|index| {
            let key = key(index);
            (key, Piece::New(Record::new(translator, key).encode()))
        })
        .collect();
    Layout::new(&translator, records).to_vec()
}

/// A pack file holding `segment` at [`BASE`], whole blocks long.
fn image(segment: &[u8]) -> Vec<u8> {
    let mut image = vec![0u8; BASE as usize + segment.len()];
    image[BASE as usize..].copy_from_slice(segment);
    image.resize(image.len().next_multiple_of(BLOCK as usize), 0);
    image
}

/// The keys of `segment`'s records in the order they lie in it.
fn layout_keys(translator: &Digest, segment: &[u8]) -> Vec<Digest> {
    let pack = Pack::parse(segment, translator).unwrap();
    let mut keys: Vec<(u64, Digest)> = pack
        .uses()
        .map(|(key, _)| (pack.locate(&key).unwrap().0, key))
        .collect();
    keys.sort();
    keys.into_iter().map(|(_, key)| key).collect()
}

fn leak(bytes: Vec<u8>) -> &'static mut [u8] {
    Box::leak(bytes.into_boxed_slice())
}

/// A preload of what `segment` (at [`BASE`]) still holds only in the file,
/// within `capacity` bytes.
fn preload(translator: &Digest, segment: &[u8], capacity: u64) -> &'static Bulk {
    let prefix = &segment[..pack::prefix_bytes(segment, translator).unwrap()];
    let from = crate::translation_store::first_left(prefix, translator, prefix.len() as u64)
        .unwrap()
        .unwrap();
    let spans = plan(
        &[Planned {
            file: BASE,
            from,
            length: segment.len() as u64,
        }],
        capacity,
    );
    let total: u64 = spans.iter().map(|span| span.length).sum();
    let memory = leak(vec![0; total as usize]);
    // SAFETY: leaked, the preload's alone.
    let bulk = unsafe { Bulk::new(memory.as_mut_ptr(), memory.len(), &spans) }.unwrap();
    Box::leak(Box::new(bulk))
}

/// The reads of one store of a pack read on demand.
struct Sim {
    translator: Digest,
    store: Store<'static>,
    segments: Vec<Pack<'static>>,
    offsets: Vec<Option<u64>>,
    bulk: Option<BulkReader<'static>>,
    flights: Vec<(Wanted, FileRead, u64)>,
    parked: Vec<Wanted>,
    retry: VecDeque<Wanted>,
    stick: Stick,
    extents: Vec<Extent>,
    /// Before the preload: the records laid out after those asked, the
    /// layout order, how far reading ahead in it went, and the mean read
    /// time in microseconds.
    launch: VecDeque<(usize, u32)>,
    order: alloc::sync::Arc<LayoutOrder>,
    cursor: usize,
    latency: u64,
    /// Records decoded from the preload's memory, and read from the stick.
    from_memory: u64,
    from_stick: u64,
}

impl Sim {
    /// A store over `segment`'s index, its records in the file `stick`
    /// holds at [`BASE`], preloaded by `bulk` when given, `chunk` bytes a
    /// bulk read.
    fn new(
        translator: Digest,
        segment: &[u8],
        stick: Stick,
        bulk: Option<&'static Bulk>,
        chunk: u64,
    ) -> Self {
        let prefix = segment[..pack::prefix_bytes(segment, &translator).unwrap()].to_vec();
        let prefix: &'static [u8] = leak(prefix);
        let segments = vec![Pack::index_only(prefix, &translator).unwrap()];
        let store = Store::over(translator, segments.clone());
        let extents = vec![Extent {
            offset: 0,
            bytes: stick.image.len() as u64,
        }];
        Self {
            translator,
            order: LayoutOrder::new(&segments),
            store,
            segments,
            offsets: vec![Some(BASE)],
            bulk: bulk.map(|bulk| BulkReader::new(bulk, chunk)),
            flights: Vec::new(),
            parked: Vec::new(),
            retry: VecDeque::new(),
            stick,
            extents,
            launch: VecDeque::new(),
            cursor: 0,
            latency: 0,
            from_memory: 0,
            from_stick: 0,
        }
    }

    fn lookup(&mut self, key: &Digest) -> Looked {
        let bulk = self.bulk.as_ref().map(BulkReader::bulk);
        lookup(&mut self.store, &self.offsets, bulk, key)
    }

    /// Give the store `wanted`'s record over `read`.
    fn give(&mut self, wanted: &Wanted, read: &[Option<&[u8]>; MAX_SEGMENTS]) {
        let decoded = self.store.read_stored(wanted, read).map(|stored| {
            DecodedRecord::decode(
                stored,
                &self.translator,
                &wanted.key,
                &mut DecodeScratch::default(),
            )
        });
        drop(
            self.store
                .finish_read(&wanted.key, wanted.bytes(), decoded.as_ref()),
        );
    }

    /// Serve `wanted` from the preload's memory, which holds it.
    fn serve(&mut self, wanted: &Wanted) {
        let bulk = self.bulk.as_ref().unwrap().bulk();
        let read = held(bulk, &self.offsets, wanted).unwrap();
        self.give(wanted, &read);
        self.from_memory += 1;
    }

    /// One step of the reader, as a PE whose guest waits takes it.
    fn step(&mut self) {
        // The record reads that ended.
        let mut at = 0;
        while at < self.flights.len() {
            if !self.flights[at].1.poll(&mut self.stick) {
                at += 1;
                continue;
            }
            let (wanted, read, started) = self.flights.swap_remove(at);
            let took = self.stick.now - started;
            self.latency = (self.latency * 7 + took) / 8;
            let mut pieces = [None; MAX_SEGMENTS];
            pieces[0] = read.bytes();
            match pieces[0] {
                Some(_) => {
                    self.give(&wanted, &pieces);
                    self.from_stick += 1;
                }
                None => drop(self.store.finish_read(&wanted.key, 0, None)),
            }
        }
        // The bulk read that ended, and the records that waited for it.
        let now = self.stick.now;
        if let Some(reader) = self.bulk.as_mut()
            && reader.collect(&mut self.stick, now)
        {
            for wanted in core::mem::take(&mut self.parked) {
                let bulk = self.bulk.as_ref().unwrap();
                match asked(bulk.bulk(), bulk, &self.offsets, &wanted) {
                    Asked::Held(_) => self.serve(&wanted),
                    Asked::Landing => self.parked.push(wanted),
                    Asked::Read => self.retry.push_back(wanted),
                }
            }
        }
        // What lookups asked for, first.
        let mut started = false;
        let most = match self.bulk {
            Some(_) => RECORD_READS,
            None => 16,
        };
        while self.flights.len() < most && self.stick.room() {
            let Some(wanted) = self.take() else {
                break;
            };
            if let Some(reader) = self.bulk.as_ref() {
                match asked(reader.bulk(), reader, &self.offsets, &wanted) {
                    Asked::Held(_) => {
                        self.serve(&wanted);
                        continue;
                    }
                    Asked::Landing => {
                        self.parked.push(wanted);
                        continue;
                    }
                    Asked::Read => {}
                }
            }
            let (offset, bytes) = wanted.pieces[0].unwrap();
            let read = FileRead::start(&mut self.stick, &self.extents, BASE + offset, bytes)
                .expect("a read in the file");
            self.flights.push((wanted, read, self.stick.now));
            started = true;
        }
        // Then the preload's next read, behind them.
        if let Some(reader) = self.bulk.as_mut() {
            started |= reader.start(&mut self.stick, &self.extents, now);
        }
        if started {
            self.stick.commit();
        }
    }

    /// The next record to read: what lookups asked; without a preload, as
    /// the boot read a disk whose reads seek, those that end within a
    /// second, the records laid out after them, then the file in layout
    /// order.
    fn take(&mut self) -> Option<Wanted> {
        if let Some(wanted) = self.retry.pop_front() {
            return Some(wanted);
        }
        let keep = (1_000_000 / self.latency.max(1)) as usize + 1;
        let _ = self.store.trim_wanted(keep);
        if self.bulk.is_some() {
            return self.store.take_wanted();
        }
        if let Some(wanted) = self.store.take_wanted() {
            let after = self.order.after(&self.segments, &wanted.key, 16);
            if self.launch.len() + after.len() <= 256 {
                self.launch.extend(after);
            }
            return Some(wanted);
        }
        while let Some((segment, index)) = self.launch.pop_front() {
            let key = self.segments[segment].key_at(index as usize);
            if let Some(wanted) = self.store.claim(&key) {
                return Some(wanted);
            }
        }
        for _ in 0..pack::AHEAD_SCAN {
            let index = self.order.nth(0, self.cursor)?;
            self.cursor += 1;
            let key = self.segments[0].key_at(index as usize);
            if let Some(wanted) = self.store.claim(&key) {
                return Some(wanted);
            }
        }
        None
    }

    /// Step every `every` microseconds until `until`.
    fn run_until(&mut self, until: u64, every: u64) {
        while self.stick.now < until {
            self.step();
            self.stick.now += every;
        }
    }
}

const TRANSLATOR: &[u8] = b"translator";

#[test]
fn a_planned_preload_takes_each_segment_s_records_left_in_the_file_within_its_capacity() {
    let segments = [
        Planned {
            file: 1000,
            from: 100,
            length: 600,
        },
        Planned {
            file: 5000,
            from: 40,
            length: 240,
        },
    ];
    assert_eq!(
        plan(&segments, u64::MAX),
        [
            Span {
                file: 1100,
                length: 500
            },
            Span {
                file: 5040,
                length: 200
            }
        ]
    );
    // The first segment's records, those its boot used first, go first.
    assert_eq!(
        plan(&segments, 300),
        [Span {
            file: 1100,
            length: 300
        }]
    );
    assert_eq!(plan(&segments, 0), []);
    // A segment read whole already takes nothing.
    let read = Planned {
        file: 0,
        from: 600,
        length: 600,
    };
    assert_eq!(plan(&[read], 1 << 20), []);
}

#[test]
fn the_records_left_begin_at_the_first_one_a_preload_cut_through() {
    let translator = Digest::of(TRANSLATOR);
    let bytes = segment(translator, 40);
    let start = pack::prefix_bytes(&bytes, &translator).unwrap();
    let prefix = &bytes[..start];
    let full = Pack::parse(&bytes, &translator).unwrap();
    let first = full
        .uses()
        .map(|(key, _)| full.locate(&key).unwrap().0)
        .min();
    assert_eq!(
        crate::translation_store::first_left(prefix, &translator, start as u64).unwrap(),
        first
    );
    // Within a record's bytes, that record is the first left.
    let (cut_at, length) = full.locate(&key(7)).unwrap();
    let left =
        crate::translation_store::first_left(prefix, &translator, cut_at + length / 2).unwrap();
    assert!(left.is_some_and(|left| left <= cut_at));
    assert_eq!(
        crate::translation_store::first_left(prefix, &translator, bytes.len() as u64).unwrap(),
        None
    );
}

/// A key no segment holds is answered from the index in memory: never read,
/// with or without a preload, read or not.
#[test]
fn a_lookup_of_an_absent_key_never_touches_the_stick() {
    let translator = Digest::of(TRANSLATOR);
    let bytes = segment(translator, 200);
    for preloaded in [false, true] {
        let bulk = preloaded.then(|| preload(&translator, &bytes, u64::MAX));
        let mut sim = Sim::new(translator, &bytes, Stick::new(image(&bytes), 1), bulk, 512);
        // Part of the preload read.
        if preloaded {
            sim.run_until(100_000, 250);
            let bulk = sim.bulk.as_ref().unwrap().bulk();
            assert!(bulk.held() > 0 && !bulk.complete());
        }
        let reads = sim.stick.reads();
        for index in 1000..1500 {
            assert!(matches!(sim.lookup(&key(index)), Looked::Absent));
        }
        assert!(sim.store.take_wanted().is_none());
        assert_eq!(sim.store.counters.awaited, 0);
        assert_eq!(sim.store.counters.absent, 500);
        assert_eq!(sim.stick.reads(), reads);
        // The reader is asked nothing for them: its reads after are the
        // preload's own.
        if preloaded {
            sim.run_until(sim.stick.now + 2_000_000, 250);
            assert_eq!(sim.from_stick, 0);
            let bulk_reads = sim.bulk.as_ref().unwrap().stats.reads as usize;
            assert_eq!(sim.stick.reads(), bulk_reads);
        }
    }
}

#[test]
fn after_a_whole_preload_no_lookup_touches_the_stick() {
    let translator = Digest::of(TRANSLATOR);
    let bytes = segment(translator, 300);
    let bulk = preload(&translator, &bytes, u64::MAX);
    let mut sim = Sim::new(
        translator,
        &bytes,
        Stick::new(image(&bytes), 1),
        Some(bulk),
        4096,
    );
    sim.run_until(60_000_000, 250);
    let reader = sim.bulk.as_ref().unwrap();
    assert_eq!(reader.stats.stopped, Some(Stopped::Whole));
    assert!(bulk.complete() && bulk.total() > 0);
    // Sequential reads of whole chunks, no more than the bytes held.
    assert_eq!(reader.stats.bytes, bulk.total());
    assert_eq!(
        reader.stats.reads,
        bulk.total().div_ceil(4096),
        "one read a chunk"
    );
    let reads = sim.stick.reads();
    for key in layout_keys(&translator, &bytes) {
        assert!(matches!(sim.lookup(&key), Looked::Found(_)), "{key:?}");
    }
    assert_eq!(sim.stick.reads(), reads, "a lookup read the stick");
    assert_eq!(sim.store.counters.awaited, 0);
    assert_eq!(sim.store.counters.loaded, 300);
    assert!(sim.store.take_wanted().is_none());
}

#[test]
fn a_preload_smaller_than_the_pack_holds_its_first_records_and_reads_the_rest_on_demand() {
    let translator = Digest::of(TRANSLATOR);
    let bytes = segment(translator, 300);
    let total = {
        let whole = preload(&translator, &bytes, u64::MAX);
        whole.total()
    };
    let bulk = preload(&translator, &bytes, total / 3);
    assert_eq!(bulk.total(), total / 3);
    let mut sim = Sim::new(
        translator,
        &bytes,
        Stick::new(image(&bytes), 1),
        Some(bulk),
        4096,
    );
    sim.run_until(30_000_000, 250);
    assert_eq!(
        sim.bulk.as_ref().unwrap().stats.stopped,
        Some(Stopped::Whole)
    );
    let keys = layout_keys(&translator, &bytes);
    let (mut held, mut asked) = (0, 0);
    let mut later = Vec::new();
    for key in &keys {
        match sim.lookup(key) {
            Looked::Found(_) => held += 1,
            Looked::Awaited => {
                asked += 1;
                later.push(*key);
            }
            Looked::Absent => panic!("a record the pack holds was lost: {key:?}"),
        }
    }
    // The records laid out first are held; those past the bound are asked.
    assert!(held > 0 && asked > 0, "{held} {asked}");
    let first_asked = keys.iter().position(|key| later.contains(key)).unwrap();
    assert!(
        keys[first_asked..].iter().all(|key| later.contains(key)),
        "the preload held records past one it left"
    );
    // Read on demand as their pages are fetched again, every one is found,
    // and only they were read alone.
    let mut left = later.clone();
    for _ in 0..600 {
        sim.run_until(sim.stick.now + 100_000, 250);
        left.retain(|key| !matches!(sim.lookup(key), Looked::Found(_)));
        if left.is_empty() {
            break;
        }
    }
    assert!(left.is_empty(), "{} records never came", left.len());
    assert_eq!(sim.from_stick as usize, later.len());
    assert_eq!(sim.store.counters.invalid, 0);
}

#[test]
fn a_record_damaged_on_the_stick_is_refused_alone() {
    let translator = Digest::of(TRANSLATOR);
    let bytes = segment(translator, 100);
    let full = Pack::parse(&bytes, &translator).unwrap();
    let bad = key(33);
    let (offset, _) = full.locate(&bad).unwrap();
    let mut image = image(&bytes);
    image[(BASE + offset) as usize + 40] ^= 0x80;
    let bulk = preload(&translator, &bytes, u64::MAX);
    let mut sim = Sim::new(translator, &bytes, Stick::new(image, 1), Some(bulk), 4096);
    sim.run_until(30_000_000, 250);
    assert!(bulk.complete());
    for key in layout_keys(&translator, &bytes) {
        let looked = sim.lookup(&key);
        if key == bad {
            assert!(
                matches!(looked, Looked::Absent),
                "a damaged record was used"
            );
        } else {
            assert!(matches!(looked, Looked::Found(_)), "{key:?}");
        }
    }
    assert_eq!(sim.store.counters.invalid, 1);
    // Refused once, it is never decoded into a block, nor read again.
    let reads = sim.stick.reads();
    assert!(matches!(sim.lookup(&bad), Looked::Absent));
    assert!(!sim.store.want(&bad));
    assert_eq!(sim.stick.reads(), reads);
}

/// A lookup's read waits behind the bulk read in flight at most: no bulk
/// read starts while it is asked or in flight, and a record inside the bulk
/// read in flight waits for it instead of being read again.
#[test]
fn a_lookup_s_read_goes_before_the_bulk_reads_queued() {
    let translator = Digest::of(TRANSLATOR);
    let bytes = segment(translator, 400);
    let bulk = preload(&translator, &bytes, u64::MAX);
    let chunk = 2048;
    let mut sim = Sim::new(
        translator,
        &bytes,
        Stick::new(image(&bytes), 1),
        Some(bulk),
        chunk,
    );
    // The first bulk read starts.
    sim.step();
    assert!(sim.bulk.as_ref().unwrap().busy());
    assert_eq!(sim.stick.reads(), 1);
    let first = sim.stick.ran[0];
    // A record far past it, and one inside it.
    let keys = layout_keys(&translator, &bytes);
    let far = *keys.last().unwrap();
    let near = keys
        .iter()
        .copied()
        .find(|key| {
            let (at, length) = sim.segments[0].locate(key).unwrap();
            sim.bulk.as_ref().unwrap().landing(BASE + at, length)
        })
        .expect("a record inside the first bulk read");
    assert!(matches!(sim.lookup(&far), Looked::Awaited));
    assert!(matches!(sim.lookup(&near), Looked::Awaited));
    sim.stick.now += 250;
    sim.step();
    // The far record's read started, and no bulk read; the near one waits
    // for the bulk read.
    assert_eq!(sim.stick.reads(), 2);
    assert_eq!(sim.parked.len(), 1);
    let record = sim.stick.ran[1];
    let (far_at, _) = sim.segments[0].locate(&far).unwrap();
    assert_eq!(
        record.lba,
        (BASE + far_at) / u64::from(BLOCK),
        "the lookup's read"
    );
    // It runs right after the bulk read in flight, and every bulk read
    // after runs after it.
    assert_eq!(record.start, first.end);
    while !sim.flights.is_empty() || !sim.parked.is_empty() {
        sim.stick.now += 250;
        sim.step();
    }
    assert!(sim.stick.ran[2..].iter().all(|ran| ran.start >= record.end));
    assert!(matches!(sim.lookup(&near), Looked::Found(_)));
    assert!(matches!(sim.lookup(&far), Looked::Found(_)));
    assert_eq!((sim.from_memory, sim.from_stick), (1, 1));
    // The preload goes on after it.
    sim.run_until(sim.stick.now + 1_000_000, 250);
    assert!(sim.stick.reads() > 2);
}

/// The launch latency model the preload was chosen with, printed: a
/// launch's lookups over the SanDisk stick's model (30 MB/s, 5-50 ms a
/// command), before and with the preload. Each record is first looked up
/// in the order its boot used it, one every 2 ms from the guest's start;
/// its page is looked up again every millisecond for 50 ms while its blocks
/// compile, after which a record that arrives is of no use. A record of the
/// model is 16 KiB (each byte of the test's empty records stands for
/// `scale` bytes).
#[test]
fn a_launch_on_a_slow_stick_finds_its_records_in_memory() {
    let translator = Digest::of(TRANSLATOR);
    let count = 3000;
    let bytes = segment(translator, count);
    let pack = Pack::parse(&bytes, &translator).unwrap();
    let mean = pack.bytes() as u64 / u64::from(count);
    let scale = (16 << 10) / mean.max(1);
    let keys = layout_keys(&translator, &bytes);
    let model_mib = (pack.bytes() as u64 * scale) >> 20;
    let run = |bulk: Option<&'static Bulk>, chunk: u64, apart: u64| -> Outcome {
        let stick = Stick::new(image(&bytes), scale);
        let mut sim = Sim::new(translator, &bytes, stick, bulk, chunk / scale);
        launch(&mut sim, &keys, apart)
    };
    eprintln!(
        "LAUNCH model: {count} records of 16 KiB ({model_mib} MiB), 30 MB/s, 5-50 ms a command"
    );
    // A launch slower than the preload reads, and one four times faster.
    for apart in [2_000, 250] {
        eprintln!("LAUNCH a first lookup every {apart} us from the guest's start:");
        let before = run(None, 0, apart);
        eprintln!("{}", before.line("before (on demand)"));
        let mut best = None;
        for chunk in [256 << 10, 1 << 20, 2 << 20, 4 << 20] {
            let bulk = preload(&translator, &bytes, u64::MAX);
            let after = run(Some(bulk), chunk, apart);
            eprintln!(
                "{}",
                after.line(&format!("background preload, {} KiB reads", chunk >> 10))
            );
            if chunk == BENCH_CHUNK {
                best = Some(after);
            }
        }
        let after = best.unwrap();
        let bulk = preload(&translator, &bytes, pack.bytes() as u64 / 2);
        let half = run(Some(bulk), BENCH_CHUNK, apart);
        eprintln!("{}", half.line("background preload of half the pack"));
        // The preload serves far more of a launch's records in time, and a
        // record waits far less for its read.
        assert!(
            after.in_time > before.in_time * 2 + 10,
            "{after:?} {before:?}"
        );
        assert!(after.p50 < before.p50, "{after:?} {before:?}");
        assert!(half.in_time > before.in_time, "{half:?} {before:?}");
    }
}

/// The bulk read size the boot uses (`stela-boot`'s `BULK_CHUNK`).
const BENCH_CHUNK: u64 = 2 << 20;

/// What a launch's lookups found: records in memory at their first lookup,
/// within the 50 ms their blocks compile, ever, and the times from a first
/// lookup to the one that found the record (median and 99th percentile, in
/// microseconds), with the stick's reads.
#[derive(Debug, Clone, Copy)]
struct Outcome {
    records: usize,
    first: usize,
    in_time: usize,
    found: usize,
    p50: u64,
    p99: u64,
    reads: usize,
}

impl Outcome {
    fn line(&self, name: &str) -> String {
        let percent = |part: usize| part * 100 / self.records.max(1);
        format!(
            "LAUNCH {name}: first lookup {}%, within 50 ms {}%, ever {}%, wait p50={} ms \
             p99={} ms, stick reads={}",
            percent(self.first),
            percent(self.in_time),
            percent(self.found),
            self.p50 / 1000,
            self.p99 / 1000,
            self.reads,
        )
    }
}

/// Run a launch over `sim`: `keys` first looked up `apart` µs apart from the
/// guest's start, each again every millisecond for 50 ms, then every 100 ms
/// to see when its record came; the reader steps every 250 µs.
fn launch(sim: &mut Sim, keys: &[Digest], apart: u64) -> Outcome {
    const AGAIN: u64 = 1_000;
    const COMPILED: u64 = 50_000;
    const SELDOM: u64 = 100_000;
    let mut first_found: Vec<Option<u64>> = vec![None; keys.len()];
    let mut first = 0;
    let end = keys.len() as u64 * apart + 60_000_000;
    // Records whose blocks compile now, and those compiled whose record
    // has not come.
    let mut compiling: VecDeque<usize> = VecDeque::new();
    let mut waiting: Vec<usize> = Vec::new();
    let (mut next_again, mut next_seldom, mut next_first) = (0, 0, 0usize);
    while sim.stick.now < end {
        let now = sim.stick.now;
        if next_first < keys.len() && now >= next_first as u64 * apart {
            let index = next_first;
            next_first += 1;
            if matches!(sim.lookup(&keys[index]), Looked::Found(_)) {
                first_found[index] = Some(0);
                first += 1;
            } else {
                compiling.push_back(index);
            }
        }
        if now >= next_again {
            next_again = now + AGAIN;
            while let Some(&index) = compiling.front() {
                if now - index as u64 * apart <= COMPILED {
                    break;
                }
                compiling.pop_front();
                if first_found[index].is_none() {
                    waiting.push(index);
                }
            }
            for &index in &compiling {
                if first_found[index].is_none()
                    && matches!(sim.lookup(&keys[index]), Looked::Found(_))
                {
                    first_found[index] = Some(now - index as u64 * apart);
                }
            }
        }
        if now >= next_seldom {
            next_seldom = now + SELDOM;
            waiting.retain(|&index| {
                let found = matches!(sim.lookup(&keys[index]), Looked::Found(_));
                if found {
                    first_found[index] = Some(now - index as u64 * apart);
                }
                !found
            });
        }
        sim.step();
        sim.stick.now += 250;
    }
    let mut waits: Vec<u64> = first_found.iter().flatten().copied().collect();
    waits.sort_unstable();
    let percentile = |part: usize| {
        let all = keys.len();
        let at = all * part / 100;
        // A record never found waits past the end.
        waits.get(at).copied().unwrap_or(end)
    };
    Outcome {
        records: keys.len(),
        first,
        in_time: waits.iter().filter(|&&wait| wait <= COMPILED).count(),
        found: waits.len(),
        p50: percentile(50),
        p99: percentile(99),
        reads: sim.stick.reads(),
    }
}

#[test]
fn file_read_splits_contiguous_extents_to_the_devices_read_transfer_limit() {
    const LIMIT: usize = 128 << 10;
    const FILE_BYTES: usize = 1 << 20;

    struct Capped {
        stick: Stick,
        sizes: Vec<usize>,
    }

    impl BlockDevice for Capped {
        fn identity(&self) -> &Identity {
            &self.stick.identity
        }
        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.stick.read(lba, buffer)
        }
        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            self.stick.write(lba, data)
        }
        fn depth(&self) -> usize {
            self.stick.depth()
        }
        fn room(&self) -> bool {
            self.stick.room()
        }
        fn start(&mut self, command: Command) -> Result<u32, BlockError> {
            if let Command::Read { bytes, .. } = command {
                if bytes > LIMIT {
                    return Err(BlockError::Protocol("read exceeded max_transfer"));
                }
                self.sizes.push(bytes);
            }
            self.stick.start(command)
        }
        fn finish(&mut self, tag: u32) -> Option<Finished> {
            self.stick.finish(tag)
        }
    }

    let image: Vec<u8> = (0..FILE_BYTES)
        .map(|i| ((i * 31 + 7) & 0xff) as u8)
        .collect();
    let mut stick = Stick::new(image.clone(), 1);
    stick.identity.features.max_transfer = LIMIT;
    let mut device = Capped {
        stick,
        sizes: Vec::new(),
    };
    let extents = [Extent {
        offset: 0,
        bytes: FILE_BYTES as u64,
    }];
    let offset = 123u64;
    let length = (512 << 10) + 777;
    let mut read = FileRead::start(&mut device, &extents, offset, length)
        .expect("a contiguous extent past max_transfer splits into valid commands");
    device.stick.now = u64::MAX / 2;
    assert!(read.poll(&mut device));
    let bytes = read.bytes().expect("every split command succeeded");
    assert_eq!(
        bytes,
        &image[offset as usize..offset as usize + length as usize]
    );
    assert!(device.sizes.len() >= 5, "sizes: {:?}", device.sizes);
    assert!(device.sizes.iter().all(|&size| size <= LIMIT));
}

#[test]
fn file_read_paces_split_chunks_within_the_devices_queue_room() {
    const LIMIT: usize = 128 << 10;
    const FILE_BYTES: usize = 1 << 20;
    const QUEUE_CAP: usize = 2;

    struct TightQueue {
        stick: Stick,
        in_flight: usize,
        peak_in_flight: usize,
        commits: usize,
    }

    impl BlockDevice for TightQueue {
        fn identity(&self) -> &Identity {
            &self.stick.identity
        }
        fn read(&mut self, lba: u64, buffer: &mut [u8]) -> Result<(), BlockError> {
            self.stick.read(lba, buffer)
        }
        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            self.stick.write(lba, data)
        }
        fn depth(&self) -> usize {
            QUEUE_CAP
        }
        fn room(&self) -> bool {
            self.in_flight < QUEUE_CAP
        }
        fn start(&mut self, command: Command) -> Result<u32, BlockError> {
            if self.in_flight >= QUEUE_CAP {
                return Err(BlockError::Protocol("the staged disk queue is full"));
            }
            if let Command::Read { bytes, .. } = command
                && bytes > LIMIT
            {
                return Err(BlockError::Protocol("read exceeded max_transfer"));
            }
            let tag = self.stick.start(command)?;
            self.in_flight += 1;
            self.peak_in_flight = self.peak_in_flight.max(self.in_flight);
            Ok(tag)
        }
        fn commit(&mut self) {
            self.commits += 1;
        }
        fn finish(&mut self, tag: u32) -> Option<Finished> {
            let result = self.stick.finish(tag)?;
            self.in_flight -= 1;
            Some(result)
        }
    }

    let image: Vec<u8> = (0..FILE_BYTES)
        .map(|i| ((i * 17 + 3) & 0xff) as u8)
        .collect();
    let mut stick = Stick::new(image.clone(), 1);
    stick.identity.features.max_transfer = LIMIT;
    let mut device = TightQueue {
        stick,
        in_flight: 0,
        peak_in_flight: 0,
        commits: 0,
    };
    let extents = [Extent {
        offset: 0,
        bytes: FILE_BYTES as u64,
    }];
    let offset = 4096 + 77;
    let length = (640 << 10) + 333;
    let mut read = FileRead::start(&mut device, &extents, offset, length)
        .expect("a tight queue accepts the first chunks without failing");
    assert_eq!(device.in_flight, QUEUE_CAP);
    let mut polls = 0;
    loop {
        device.stick.now = device.stick.busy_until;
        polls += 1;
        if read.poll(&mut device) {
            break;
        }
        assert!(polls < 32, "read did not complete");
    }
    assert_eq!(device.in_flight, 0);
    assert_eq!(device.peak_in_flight, QUEUE_CAP);
    assert!(device.commits >= 2, "later chunks must ring commit()");
    let bytes = read.bytes().expect("every paced chunk succeeded");
    assert_eq!(
        bytes,
        &image[offset as usize..offset as usize + length as usize]
    );
}

#[test]
fn staged_writes_split_to_max_transfer_pace_on_room_and_reset_on_error() {
    use stela_formats::journal::Target;

    const LIMIT: usize = 1024;
    const QUEUE_CAP: usize = 2;
    const FILE_BYTES: usize = 8192;

    struct TightWriteQueue {
        identity: Identity,
        image: Vec<u8>,
        pending: BTreeMap<u32, (u64, Vec<u8>, bool)>,
        next_tag: u32,
        peak_in_flight: usize,
        commits: usize,
        writes_started: usize,
        fail_finish_on: Option<usize>,
        fail_start_on: Option<usize>,
        /// Keep this tag in flight (`finish` returns `None`) for `remaining`
        /// finish polls before completing it.
        hold_finish: Option<(u32, usize)>,
    }

    impl TightWriteQueue {
        fn new() -> Self {
            Self {
                identity: Identity {
                    transport: Transport::Nvme,
                    location: String::from("fake-nvme"),
                    model: String::from("tight-write"),
                    serial: String::new(),
                    blocks: (FILE_BYTES / BLOCK as usize) as u64,
                    block_size: BLOCK,
                    read_only: false,
                    features: Features {
                        max_transfer: LIMIT,
                        ..Features::default()
                    },
                },
                image: vec![0u8; FILE_BYTES],
                pending: BTreeMap::new(),
                next_tag: 1,
                peak_in_flight: 0,
                commits: 0,
                writes_started: 0,
                fail_finish_on: None,
                fail_start_on: None,
                hold_finish: None,
            }
        }
    }

    impl BlockDevice for TightWriteQueue {
        fn identity(&self) -> &Identity {
            &self.identity
        }
        fn read(&mut self, _lba: u64, _buffer: &mut [u8]) -> Result<(), BlockError> {
            Err(BlockError::Unsupported("write-only test device"))
        }
        fn write(&mut self, lba: u64, data: &[u8]) -> Result<(), BlockError> {
            let start = (lba * u64::from(BLOCK)) as usize;
            self.image[start..start + data.len()].copy_from_slice(data);
            Ok(())
        }
        fn depth(&self) -> usize {
            QUEUE_CAP
        }
        fn room(&self) -> bool {
            self.pending.len() < QUEUE_CAP
        }
        fn start(&mut self, command: Command) -> Result<u32, BlockError> {
            if self.pending.len() >= QUEUE_CAP {
                return Err(BlockError::Protocol("the staged disk queue is full"));
            }
            let Command::Write { lba, data, .. } = command else {
                return Err(BlockError::Unsupported("unexpected command"));
            };
            assert!(
                data.len() <= LIMIT,
                "staged write chunk {} exceeded max_transfer {LIMIT}",
                data.len()
            );
            self.writes_started += 1;
            if self.fail_start_on == Some(self.writes_started) {
                return Err(BlockError::Protocol("injected start failure"));
            }
            let fail_finish = self.fail_finish_on == Some(self.writes_started);
            let tag = self.next_tag;
            self.next_tag += 1;
            self.pending.insert(tag, (lba, data, fail_finish));
            self.peak_in_flight = self.peak_in_flight.max(self.pending.len());
            Ok(tag)
        }
        fn commit(&mut self) {
            self.commits += 1;
        }
        fn finish(&mut self, tag: u32) -> Option<Finished> {
            if let Some((held, remaining)) = self.hold_finish.as_mut()
                && *held == tag
                && *remaining > 0
            {
                *remaining -= 1;
                return None;
            }
            let (lba, data, fail) = self.pending.remove(&tag)?;
            if fail {
                return Some(Err(BlockError::Protocol("injected completion failure")));
            }
            let start = (lba * u64::from(BLOCK)) as usize;
            self.image[start..start + data.len()].copy_from_slice(&data);
            Some(Ok(None))
        }
    }

    let extents = [
        Extent {
            offset: 0,
            bytes: 3072,
        },
        Extent {
            offset: 4096,
            bytes: 4096,
        },
    ];
    let payload: Vec<u8> = (0..5120).map(|i| ((i * 29 + 7) & 0xff) as u8).collect();
    let offset = 1024;

    // 1. Paced write splits into <= max_transfer chunks and honors room().
    let mut device = TightWriteQueue::new();
    let mut queued = Queued::default();
    let mut polls = 0;
    loop {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        polls += 1;
        if staged
            .write_at(offset, &payload)
            .expect("paced write succeeds")
        {
            break;
        }
        assert!(polls < 16, "staged write did not finish");
    }
    assert_eq!(device.peak_in_flight, QUEUE_CAP);
    assert!(device.commits >= 3);
    assert_eq!(&device.image[1024..3072], &payload[..2048]);
    assert_eq!(&device.image[4096..4096 + 3072], &payload[2048..]);

    // 2. A completion error on one in-flight tag resets `queued` so retrying at
    // the exact same offset re-submits and writes every byte instead of
    // skipping setup and reporting false success.
    let mut device = TightWriteQueue::new();
    device.fail_finish_on = Some(1);
    let mut queued = Queued::default();
    {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        assert_eq!(staged.write_at(offset, &payload), Ok(false));
        assert!(staged.write_at(offset, &payload).is_err());
    }
    assert!(device.pending.is_empty(), "abort drained remaining tag");
    device.image.fill(0);
    device.fail_finish_on = None;
    let started_before_retry = device.writes_started;
    let mut polls = 0;
    loop {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        polls += 1;
        if staged
            .write_at(offset, &payload)
            .expect("retry at same offset succeeds")
        {
            break;
        }
        assert!(polls < 16, "retry write did not finish");
    }
    assert!(
        device.writes_started > started_before_retry,
        "retry at the same offset must re-submit commands"
    );
    assert_eq!(&device.image[1024..3072], &payload[..2048]);
    assert_eq!(&device.image[4096..4096 + 3072], &payload[2048..]);

    // 3. A start_more error after partial submission also commits started tags,
    // drains/abandons them, and resets `queued` for a clean retry at the same
    // offset.
    let mut device = TightWriteQueue::new();
    device.fail_start_on = Some(2);
    let mut queued = Queued::default();
    {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        assert!(staged.write_at(offset, &payload).is_err());
    }
    assert_eq!(device.commits, 1);
    assert!(device.pending.is_empty());
    device.image.fill(0);
    device.fail_start_on = None;
    loop {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        if staged
            .write_at(offset, &payload)
            .expect("retry after start error succeeds")
        {
            break;
        }
    }
    assert_eq!(&device.image[1024..3072], &payload[..2048]);
    assert_eq!(&device.image[4096..4096 + 3072], &payload[2048..]);

    // 4. Commands still in flight when an error aborts the write are retained
    // in `abandoned` and collected on subsequent turns so no queue slot is
    // permanently leaked and retries wait until in-flight tags finish.
    let mut device = TightWriteQueue::new();
    device.fail_finish_on = Some(1);
    device.hold_finish = Some((2, 2)); // tag 2 stays in flight across abort + 1 poll
    let mut queued = Queued::default();
    {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        assert_eq!(staged.write_at(offset, &payload), Ok(false));
        assert!(staged.write_at(offset, &payload).is_err());
    }
    assert_eq!(
        device.pending.len(),
        1,
        "tag 2 must still be in flight after abort"
    );
    device.fail_finish_on = None;
    let started_before_drain = device.writes_started;
    {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        // First retry poll: tag 2 is still not ready -> no new writes started yet.
        assert_eq!(staged.write_at(offset, &payload), Ok(false));
        assert_eq!(device.writes_started, started_before_drain);
        assert_eq!(device.pending.len(), 1);
    }
    device.image.fill(0);
    let mut polls = 0;
    loop {
        let mut staged = Staged {
            device: &mut device,
            extents: &extents,
            queued: &mut queued,
        };
        polls += 1;
        if staged
            .write_at(offset, &payload)
            .expect("retry succeeds after abandoned tag is collected")
        {
            break;
        }
        assert!(polls < 16, "retry after abandoned drain did not finish");
    }
    assert!(
        device.pending.is_empty(),
        "every abandoned tag slot must be reclaimed"
    );
    assert_eq!(&device.image[1024..3072], &payload[..2048]);
    assert_eq!(&device.image[4096..4096 + 3072], &payload[2048..]);
}

// Measures the physical on-disk layout of the streams in a `.vpx` (OLE compound) file.
//
// Why this exists: VPinball PR #3817 sped up cold table loads by reading streams
// in ascending physical file-offset order instead of declaration order. On some
// tables most reads run backwards through the file, defeating OS readahead. This
// tool measures how forward- or backward-ordered a table's streams actually are,
// so a claim about layout is a measurement rather than an inference.
//
// It parses the MS-CFB structure directly (header, DIFAT, FAT, directory chain)
// to recover each stream's starting sector and therefore its physical byte
// offset. The public `cfb` API does not expose starting sectors, so the offsets
// are parsed here and cross-checked against `cfb`'s own `walk()` for the set of
// stream paths and lengths, so the parse is proven rather than trusted.
//
// Streams below the 4096-byte mini-stream cutoff live in the shared mini stream,
// a separate coordinate space, so they are reported separately and excluded from
// the regular-chain offset ordering.
//
// Usage:
//   cargo run --release --example stream_layout -- <file.vpx> [read-order]
//   cargo run --release --example stream_layout -- <folder> [read-order]
//
// read-order selects which reader's stream walk the backward-read fraction is
// computed against. Default is `vpinball`.
//   vpinball  GameItem, then Sound, then Image, then the rest (the C++ loader walk)
//   vpin      GameItem, then Image, then Sound (this crate's own read order)
//   offset    already sorted by physical offset (the #3817-patched reader); always 0% backward

use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const DIR_ENTRY_LEN: usize = 128;
const MINI_STREAM_CUTOFF: u64 = 4096;
const END_OF_CHAIN: u32 = 0xFFFF_FFFE;
const FREE_SECTOR: u32 = 0xFFFF_FFFF;
const MAX_REGULAR_SECTOR: u32 = 0xFFFF_FFFA;
const NUM_DIFAT_IN_HEADER: usize = 109;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadOrder {
    VPinball,
    Vpin,
    Offset,
}

impl ReadOrder {
    fn parse(s: &str) -> Option<ReadOrder> {
        match s.to_lowercase().as_str() {
            "vpinball" | "vpx" => Some(ReadOrder::VPinball),
            "vpin" => Some(ReadOrder::Vpin),
            "offset" => Some(ReadOrder::Offset),
            _ => None,
        }
    }
    fn label(self) -> &'static str {
        match self {
            ReadOrder::VPinball => "vpinball (GameItem, Sound, Image, rest)",
            ReadOrder::Vpin => "vpin (GameItem, Image, Sound, rest)",
            ReadOrder::Offset => "offset (physical, always forward)",
        }
    }
}

#[derive(Clone)]
struct StreamInfo {
    path: String,
    len: u64,
    /// Physical byte offset in the file. `None` for mini-stream members, whose
    /// start_sector indexes the mini stream rather than the file.
    offset: Option<u64>,
    is_mini: bool,
}

struct Layout {
    sector_len: u64,
    streams: Vec<StreamInfo>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "Usage: {} <file.vpx | folder> [vpinball|vpin|offset]",
            args[0]
        );
        std::process::exit(1);
    }
    let target = PathBuf::from(&args[1]);
    let order = match args.get(2) {
        Some(s) => match ReadOrder::parse(s) {
            Some(o) => o,
            None => {
                eprintln!("Unknown read order: {s}. Use vpinball, vpin, or offset.");
                std::process::exit(1);
            }
        },
        None => ReadOrder::VPinball,
    };

    let mut vpx_files: Vec<PathBuf> = Vec::new();
    if target.is_dir() {
        for entry in walkdir::WalkDir::new(&target)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|x| x.eq_ignore_ascii_case("vpx"))
                    .unwrap_or(false)
            })
        {
            vpx_files.push(entry.path().to_path_buf());
        }
        vpx_files.sort();
    } else {
        vpx_files.push(target);
    }

    println!("Read order: {}\n", order.label());
    for path in &vpx_files {
        match report(path, order) {
            Ok(()) => {}
            Err(e) => eprintln!("Error on {}: {}", path.display(), e),
        }
    }
    Ok(())
}

fn report(path: &Path, order: ReadOrder) -> Result<(), Box<dyn std::error::Error>> {
    let layout = parse_layout(path)?;
    validate_against_cfb(path, &layout)?;

    let read_paths = read_walk(&layout, order);
    let (backward, considered, backward_bytes, considered_bytes) =
        backward_fraction(&layout, &read_paths);

    let regular: Vec<&StreamInfo> = layout.streams.iter().filter(|s| !s.is_mini).collect();
    let mini: Vec<&StreamInfo> = layout.streams.iter().filter(|s| s.is_mini).collect();
    let mini_bytes: u64 = mini.iter().map(|s| s.len).sum();
    let regular_bytes: u64 = regular.iter().map(|s| s.len).sum();

    println!("=== {}", path.display());
    println!(
        "  sector size {} B, streams: {} regular, {} mini (< {} B)",
        layout.sector_len,
        regular.len(),
        mini.len(),
        MINI_STREAM_CUTOFF
    );
    println!(
        "  bytes: {:.1} MB regular, {:.1} KB mini",
        regular_bytes as f64 / 1_048_576.0,
        mini_bytes as f64 / 1024.0
    );
    if considered > 0 {
        println!(
            "  backward reads (by count): {}/{} = {:.1}%",
            backward,
            considered,
            100.0 * backward as f64 / considered as f64
        );
        println!(
            "  backward reads (by bytes): {:.1}/{:.1} MB = {:.1}%",
            backward_bytes as f64 / 1_048_576.0,
            considered_bytes as f64 / 1_048_576.0,
            100.0 * backward_bytes as f64 / considered_bytes.max(1) as f64
        );
    } else {
        println!("  backward reads: n/a (no regular streams in read walk)");
    }
    println!();
    Ok(())
}

/// Fraction of consecutive reads (in the reader's walk order, restricted to
/// regular-chain streams) whose physical offset is lower than the previous
/// read's, i.e. a backward seek that defeats readahead.
fn backward_fraction(
    layout: &Layout,
    read_paths: &[String],
) -> (usize, usize, u64, u64) {
    let by_path: HashMap<&str, &StreamInfo> =
        layout.streams.iter().map(|s| (s.path.as_str(), s)).collect();

    let seq: Vec<(&str, u64, u64)> = read_paths
        .iter()
        .filter_map(|p| by_path.get(p.as_str()))
        .filter(|s| !s.is_mini)
        .filter_map(|s| s.offset.map(|o| (s.path.as_str(), o, s.len)))
        .collect();

    let verbose = std::env::var("VERBOSE").is_ok();
    let mut backward = 0usize;
    let mut backward_bytes = 0u64;
    let mut considered_bytes = 0u64;
    for w in seq.windows(2) {
        let (prev_name, prev, _) = w[0];
        let (cur_name, cur, cur_len) = w[1];
        considered_bytes += cur_len;
        if cur < prev {
            backward += 1;
            backward_bytes += cur_len;
            if verbose {
                println!(
                    "    BACKWARD: {cur_name} @ {cur} ({} KB) follows {prev_name} @ {prev}, seek back {} KB",
                    cur_len / 1024,
                    (prev - cur) / 1024
                );
            }
        }
    }
    let considered = seq.len().saturating_sub(1);
    (backward, considered, backward_bytes, considered_bytes)
}

/// Orders stream paths the way the selected reader would walk them.
fn read_walk(layout: &Layout, order: ReadOrder) -> Vec<String> {
    let mut paths: Vec<String> = layout.streams.iter().map(|s| s.path.clone()).collect();

    if order == ReadOrder::Offset {
        paths.sort_by_key(|p| {
            layout
                .streams
                .iter()
                .find(|s| &s.path == p)
                .and_then(|s| s.offset)
                .unwrap_or(u64::MAX)
        });
        return paths;
    }

    // Group rank for the two declaration-order readers. Lower rank is read first.
    let group_rank = |p: &str| -> u32 {
        let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
        let is = |prefix: &str| name.starts_with(prefix);
        match order {
            ReadOrder::VPinball => {
                if is("GameItem") {
                    0
                } else if is("Sound") {
                    1
                } else if is("Image") {
                    2
                } else {
                    3
                }
            }
            ReadOrder::Vpin => {
                if is("GameItem") {
                    0
                } else if is("Image") {
                    1
                } else if is("Sound") {
                    2
                } else {
                    3
                }
            }
            ReadOrder::Offset => 0,
        }
    };
    let index_of = |p: &str| -> u32 {
        let name = p.rsplit(['/', '\\']).next().unwrap_or(p);
        let digits: String = name.chars().filter(|c| c.is_ascii_digit()).collect();
        digits.parse().unwrap_or(0)
    };
    paths.sort_by(|a, b| {
        group_rank(a)
            .cmp(&group_rank(b))
            .then(index_of(a).cmp(&index_of(b)))
    });
    paths
}

// --- MS-CFB physical layout parse -----------------------------------------

fn parse_layout(path: &Path) -> io::Result<Layout> {
    let mut file = File::open(path)?;
    let mut header = [0u8; 512];
    file.read_exact(&mut header)?;
    if header[0..8] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a compound file (bad magic)",
        ));
    }
    let version = u16::from_le_bytes([header[26], header[27]]);
    let sector_shift = u16::from_le_bytes([header[30], header[31]]);
    let sector_len: u64 = 1u64 << sector_shift;
    if version != 3 && version != 4 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported CFB version {version}"),
        ));
    }
    let num_fat_sectors = u32::from_le_bytes([header[44], header[45], header[46], header[47]]);
    let first_dir_sector = u32::from_le_bytes([header[48], header[49], header[50], header[51]]);
    let first_difat_sector = u32::from_le_bytes([header[68], header[69], header[70], header[71]]);
    let num_difat_sectors = u32::from_le_bytes([header[72], header[73], header[74], header[75]]);

    // Collect FAT sector ids: first the 109 in the header, then follow the DIFAT chain.
    let mut fat_sector_ids: Vec<u32> = Vec::with_capacity(num_fat_sectors as usize);
    for i in 0..NUM_DIFAT_IN_HEADER {
        let off = 76 + i * 4;
        let s = u32::from_le_bytes([header[off], header[off + 1], header[off + 2], header[off + 3]]);
        if s == FREE_SECTOR || s > MAX_REGULAR_SECTOR {
            continue;
        }
        fat_sector_ids.push(s);
    }
    let entries_per_sector = (sector_len / 4) as usize;
    let mut difat = first_difat_sector;
    let mut difat_guard = 0u32;
    while difat != END_OF_CHAIN && difat != FREE_SECTOR && difat <= MAX_REGULAR_SECTOR {
        let sec = read_sector(&mut file, difat, sector_len)?;
        for i in 0..(entries_per_sector - 1) {
            let off = i * 4;
            let s = u32::from_le_bytes([sec[off], sec[off + 1], sec[off + 2], sec[off + 3]]);
            if s != FREE_SECTOR && s <= MAX_REGULAR_SECTOR {
                fat_sector_ids.push(s);
            }
        }
        let last = (entries_per_sector - 1) * 4;
        difat = u32::from_le_bytes([sec[last], sec[last + 1], sec[last + 2], sec[last + 3]]);
        difat_guard += 1;
        if difat_guard > num_difat_sectors + 1 {
            break;
        }
    }

    // Read the full FAT into a flat vector of next-sector pointers.
    let mut fat: Vec<u32> = Vec::with_capacity(fat_sector_ids.len() * entries_per_sector);
    for &sid in &fat_sector_ids {
        let sec = read_sector(&mut file, sid, sector_len)?;
        for i in 0..entries_per_sector {
            let off = i * 4;
            fat.push(u32::from_le_bytes([
                sec[off],
                sec[off + 1],
                sec[off + 2],
                sec[off + 3],
            ]));
        }
    }

    // Follow the directory chain and parse every 128-byte entry.
    let dir_sectors = follow_chain(&fat, first_dir_sector);
    let mut streams: Vec<StreamInfo> = Vec::new();
    for &sid in &dir_sectors {
        let sec = read_sector(&mut file, sid, sector_len)?;
        let per_sector = sector_len as usize / DIR_ENTRY_LEN;
        for i in 0..per_sector {
            let base = i * DIR_ENTRY_LEN;
            let entry = &sec[base..base + DIR_ENTRY_LEN];
            if let Some(info) = parse_dir_entry(entry, sector_len) {
                streams.push(info);
            }
        }
    }

    Ok(Layout {
        sector_len,
        streams,
    })
}

fn parse_dir_entry(entry: &[u8], sector_len: u64) -> Option<StreamInfo> {
    let name_len_bytes = u16::from_le_bytes([entry[64], entry[65]]) as usize;
    if name_len_bytes == 0 || name_len_bytes > 64 {
        return None;
    }
    let obj_type = entry[66];
    // 0 unallocated, 1 storage, 2 stream, 5 root
    if obj_type != 2 {
        return None;
    }
    let name_units = name_len_bytes / 2 - 1;
    let mut name = String::with_capacity(name_units);
    for i in 0..name_units {
        let c = u16::from_le_bytes([entry[i * 2], entry[i * 2 + 1]]);
        if c == 0 {
            break;
        }
        name.push(char::from_u32(c as u32).unwrap_or('\u{FFFD}'));
    }
    let start_sector = u32::from_le_bytes([entry[116], entry[117], entry[118], entry[119]]);
    let stream_len = u64::from_le_bytes([
        entry[120], entry[121], entry[122], entry[123], entry[124], entry[125], entry[126],
        entry[127],
    ]);
    // V3 masks stream_len to 32 bits; both versions are safe to mask high bits
    // that some writers leave nonzero, matching cfb's stream_len_mask handling.
    let stream_len = if sector_len == 512 {
        stream_len & 0x0000_0000_FFFF_FFFF
    } else {
        stream_len
    };

    let is_mini = stream_len < MINI_STREAM_CUTOFF;
    let offset = if is_mini {
        None
    } else if start_sector <= MAX_REGULAR_SECTOR {
        Some((start_sector as u64 + 1) * sector_len)
    } else {
        None
    };
    Some(StreamInfo {
        path: name,
        len: stream_len,
        offset,
        is_mini,
    })
}

fn follow_chain(fat: &[u32], start: u32) -> Vec<u32> {
    let mut out = Vec::new();
    let mut cur = start;
    let mut guard = 0usize;
    while cur != END_OF_CHAIN && cur != FREE_SECTOR && (cur as usize) < fat.len() {
        out.push(cur);
        cur = fat[cur as usize];
        guard += 1;
        if guard > fat.len() {
            break;
        }
    }
    out
}

fn read_sector(file: &mut File, sector_id: u32, sector_len: u64) -> io::Result<Vec<u8>> {
    let offset = (sector_id as u64 + 1) * sector_len;
    file.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; sector_len as usize];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Cross-check the hand-rolled parse against cfb's public walk(): the set of
/// stream leaf-names and their lengths must match. This proves the lever reads
/// the same streams cfb does, without trusting the offset math.
fn validate_against_cfb(path: &Path, layout: &Layout) -> Result<(), Box<dyn std::error::Error>> {
    let comp = cfb::open(path)?;
    let mut cfb_streams: HashMap<String, u64> = HashMap::new();
    for entry in comp.walk() {
        if entry.is_stream() {
            let leaf = entry
                .path()
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            cfb_streams.insert(leaf, entry.len());
        }
    }
    let mut ours: HashMap<String, u64> = HashMap::new();
    for s in &layout.streams {
        ours.insert(s.path.clone(), s.len);
    }
    if ours.len() != cfb_streams.len() {
        return Err(format!(
            "parse mismatch: parsed {} streams, cfb walk found {}",
            ours.len(),
            cfb_streams.len()
        )
        .into());
    }
    for (name, len) in &cfb_streams {
        match ours.get(name) {
            Some(our_len) if our_len == len => {}
            Some(our_len) => {
                return Err(format!(
                    "length mismatch for {name}: parsed {our_len}, cfb {len}"
                )
                .into());
            }
            None => return Err(format!("cfb stream {name} not found by parse").into()),
        }
    }
    Ok(())
}

// Surveys the image payload of a whole table library and measures how much a
// lossless re-encode and/or downscale would save, per image. Writes one CSV row
// per image plus a per-table summary row, and logs progress per table.
//
// SAFETY: this tool is read-only with respect to the input library. It opens
// every table with a read-only handle (vpx::read), never writes into the input
// tree, and refuses to run if the CSV output path is inside the input root.
// Size savings are computed entirely in memory (decode, re-encode, measure,
// discard). Nothing on disk is modified.
//
// Usage:
//   cargo run --release --example image_survey -- <tables_root> <out.csv>
//
// Tables are expected at <tables_root>/<Name>/<Name>.vpx (one level deep, the
// vpx file shares its parent folder's name). Tables are processed in sorted
// order. This tool holds the SYSTEM awake for the run via caffeinate (the
// display may still sleep); keep the lid open, since closing it triggers
// clamshell sleep that caffeinate does not override.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use image::{DynamicImage, ImageFormat, imageops::FilterType};
use rayon::prelude::*;
use vpin::vpx;
use vpin::vpx::image::{ImageData, image_has_transparency};

/// Per-format census across the whole run. Keyed by a human label describing
/// what the bytes actually are (sniffed for encoded images, "bmp/bits" for the
/// LZW bitmap carrier, "path:<ext>" when we cannot sniff or decode).
#[derive(Default)]
struct FormatCensus {
    entries: BTreeMap<String, FormatStat>,
}

#[derive(Default)]
struct FormatStat {
    count: u64,
    stored_bytes: u64,
    decoded_ok: u64,
    decode_failed: u64,
}

impl FormatCensus {
    fn record(&mut self, label: &str, stored: u64, decoded_ok: bool, failed: bool) {
        let e = self.entries.entry(label.to_string()).or_default();
        e.count += 1;
        e.stored_bytes += stored;
        if decoded_ok {
            e.decoded_ok += 1;
        }
        if failed {
            e.decode_failed += 1;
        }
    }
}

/// Per-format census for sounds. Sound is stored verbatim (no decode), so we
/// only track how many and how many bytes per format, keyed by path extension.
#[derive(Default)]
struct SoundCensus {
    entries: BTreeMap<String, (u64, u64)>, // label -> (count, stored_bytes)
}

impl SoundCensus {
    fn record(&mut self, label: &str, stored: u64) {
        let e = self.entries.entry(label.to_string()).or_default();
        e.0 += 1;
        e.1 += stored;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Usage: {} <tables_root> <out.csv> [vpinball_scripts_dir]",
            args[0]
        );
        eprintln!(
            "  vpinball_scripts_dir: optional. If given, literal names in the shared\n\
             \x20 include scripts (core.vbs, controller.vbs, ROM-family .vbs) are treated as\n\
             \x20 referenced-by-convention, so assets used only via includes are not flagged\n\
             \x20 unreferenced."
        );
        std::process::exit(1);
    }
    let root = PathBuf::from(&args[1]);
    let out_csv = PathBuf::from(&args[2]);
    let scripts_dir = args.get(3).map(PathBuf::from);

    if !root.is_dir() {
        eprintln!("Tables root is not a directory: {}", root.display());
        std::process::exit(1);
    }
    // Safety guard: never allow output inside the (possibly read-only, possibly
    // network) input tree. This makes accidental writes into the library
    // structurally impossible rather than merely intended.
    let root_abs = root.canonicalize()?;
    if let Ok(out_abs) = out_csv
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        && out_abs.starts_with(&root_abs)
    {
        eprintln!(
            "Refusing to write output inside the input library ({}). Choose a path outside it.",
            root_abs.display()
        );
        std::process::exit(1);
    }

    // Hold the machine awake for the duration. caffeinate is spawned as a child
    // tied to our lifetime (-w our pid), and it is killed when we exit, so idle
    // sleep is restored automatically without any teardown step of our own.
    let _caffeinate = spawn_caffeinate();

    // Convention allowlist from the shared VPinball include scripts. Any literal
    // name they reference (asset names, dictionary keys) is treated as used-by-
    // convention so a table asset bound only via an include is not flagged
    // unreferenced. Broad by design (all quoted literals), which errs toward
    // "used", the safe direction for orphan detection.
    let convention = match &scripts_dir {
        Some(dir) => {
            let set = load_convention_names(dir);
            println!(
                "Loaded {} convention names from include scripts at {}",
                set.len(),
                dir.display()
            );
            set
        }
        None => {
            println!(
                "No scripts dir given: assets referenced only via external includes may be \
                 flagged unreferenced (low confidence for tables with includes)."
            );
            HashSet::new()
        }
    };

    let tables = enumerate_tables(&root);
    println!("Found {} tables under {}", tables.len(), root.display());

    let mut csv = File::create(&out_csv)?;
    writeln!(
        csv,
        "table,image_name,path_ext,detected_format,source_kind,decoded,skipped_reason,is_link,\
         unreferenced,table_uses_includes,transparent,width,height,stored_bytes,\
         lossless_webp_bytes,q90_bytes,q90_ssim2,q80_bytes,q80_ssim2,\
         r50_bytes,r50_ssim2,r25_bytes,r25_ssim2,lossless_opt_bytes,lossy_opt_bytes,decode_error"
    )?;

    // Dedicated decode-failure log. With decode limits lifted, EXR/HDR (and
    // everything else) should decode, so any row here is an anomaly to follow
    // up. Kept separate from the main CSV so failures are never lost in the
    // thousands of image rows.
    let fail_csv = out_csv.with_extension("decode-failures.csv");
    let mut failures = File::create(&fail_csv)?;
    writeln!(
        failures,
        "table,image_name,path_ext,detected_format,width,height,stored_bytes,error"
    )?;

    let mut census = FormatCensus::default();
    let mut sound_census = SoundCensus::default();
    let run_start = Instant::now();
    let mut ok = 0usize;
    let mut failed = 0usize;
    let mut decode_failures = 0usize;
    let mut skipped_total = 0usize;

    for (i, table) in tables.iter().enumerate() {
        let t0 = Instant::now();
        let label = table
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        print!("{} [{}/{}] {} ... ", timestamp(), i + 1, tables.len(), label);
        io::stdout().flush().ok();

        match survey_table(
            table,
            &mut csv,
            &mut failures,
            &mut census,
            &mut sound_census,
            &convention,
        ) {
            Ok(stats) => {
                ok += 1;
                decode_failures += stats.decode_failures;
                skipped_total += stats.skipped_count;
                let mut flag = String::new();
                if stats.skipped_count > 0 {
                    flag.push_str(&format!(", {} skipped", stats.skipped_count));
                }
                if stats.decode_failures > 0 {
                    flag.push_str(&format!(", {} DECODE FAILURES", stats.decode_failures));
                }
                let orphan_note = if stats.unref_count > 0 {
                    // Confidence: high when the table has no includes, or when
                    // it has includes but we loaded the convention set to
                    // resolve them. Low only when includes are present and we
                    // had no scripts dir to resolve them against.
                    let conf = if !stats.uses_includes {
                        "no includes"
                    } else if !convention.is_empty() {
                        "includes resolved"
                    } else {
                        "includes unresolved"
                    };
                    format!(
                        " | {} unref ({:.1} MB, {})",
                        stats.unref_count,
                        stats.unref_bytes as f64 / 1_048_576.0,
                        conf
                    )
                } else {
                    String::new()
                };
                println!(
                    "{} images, {:.1} MB | lossless -> {:.1} MB ({:.0}%) | lossy80 -> {:.1} MB ({:.0}%){}{}, {:.2}s{}",
                    stats.image_count,
                    stats.stored as f64 / 1_048_576.0,
                    stats.lossless_total as f64 / 1_048_576.0,
                    pct_saved(stats.stored, stats.lossless_total),
                    stats.lossy_total as f64 / 1_048_576.0,
                    pct_saved(stats.stored, stats.lossy_total),
                    ssim_note(&stats),
                    orphan_note,
                    t0.elapsed().as_secs_f64(),
                    flag,
                );
            }
            Err(e) => {
                failed += 1;
                println!("FAILED: {e}");
            }
        }
        csv.flush().ok();
    }

    // Format census: write companion CSVs and print summaries to the console.
    let formats_csv = out_csv.with_extension("formats.csv");
    write_census(&census, &formats_csv)?;
    let sound_csv = out_csv.with_extension("sound-formats.csv");
    write_sound_census(&sound_census, &sound_csv)?;

    println!(
        "\nDone. {} tables surveyed, {} table read errors, {} skipped images (PSD/exotic/LUT), \
         {} genuine decode failures, in {:.1} min.\
         \n  images CSV:   {}\n  formats CSV:  {}\n  failures CSV: {}",
        ok,
        failed,
        skipped_total,
        decode_failures,
        run_start.elapsed().as_secs_f64() / 60.0,
        out_csv.display(),
        formats_csv.display(),
        fail_csv.display(),
    );
    if decode_failures > 0 {
        println!(
            "\n  NOTE: {decode_failures} images in a SUPPORTED format failed to decode. This is \
             unexpected (skipped formats like PSD are counted separately, not here); see {} \
             for table/name/format/dims to follow up.",
            fail_csv.display()
        );
    }

    println!("\nImage format census (by count, stored bytes, decode outcome):");
    println!(
        "  {:<16} {:>8} {:>12} {:>10} {:>10}",
        "format", "count", "stored_MB", "decoded", "failed"
    );
    for (label, s) in &census.entries {
        println!(
            "  {:<16} {:>8} {:>12.1} {:>10} {:>10}",
            label,
            s.count,
            s.stored_bytes as f64 / 1_048_576.0,
            s.decoded_ok,
            s.decode_failed,
        );
    }

    println!("\nSound format census (by count, stored bytes):");
    println!("  {:<16} {:>8} {:>12}", "format", "count", "stored_MB");
    for (label, (count, bytes)) in &sound_census.entries {
        println!(
            "  {:<16} {:>8} {:>12.1}",
            label,
            count,
            *bytes as f64 / 1_048_576.0,
        );
    }
    Ok(())
}

fn write_sound_census(census: &SoundCensus, path: &Path) -> io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "format,count,stored_bytes")?;
    for (label, (count, bytes)) in &census.entries {
        writeln!(f, "{},{},{}", csv_escape(label), count, bytes)?;
    }
    Ok(())
}

fn write_census(census: &FormatCensus, path: &Path) -> io::Result<()> {
    let mut f = File::create(path)?;
    writeln!(f, "format,count,stored_bytes,decoded_ok,decode_failed")?;
    for (label, s) in &census.entries {
        writeln!(
            f,
            "{},{},{},{},{}",
            csv_escape(label),
            s.count,
            s.stored_bytes,
            s.decoded_ok,
            s.decode_failed,
        )?;
    }
    Ok(())
}

struct TableStats {
    image_count: usize,
    stored: u64,
    /// Sum of per-image fidelity-preserving optimised size: lossless WebP where
    /// the source is lossless and it helps, else the original bytes. Never
    /// exceeds stored. This is the "no quality loss" figure.
    lossless_total: u64,
    /// Sum of per-image lossy-WebP (quality 80) optimised size at full
    /// resolution, where that beats the original. Never exceeds stored. This is
    /// the "accept quality-80" figure.
    lossy_total: u64,
    /// Number of images that genuinely failed to decode (a supported format
    /// that errored, or a stream with no pixel data). Any nonzero count is an
    /// anomaly logged to the failures CSV. Does NOT include skipped images
    /// (see `skipped_count`).
    decode_failures: usize,
    /// Number of images an optimise would skip (PSD/exotic formats, LUTs). A
    /// normal outcome, reported for the census, not a failure.
    skipped_count: usize,
    /// Total stored bytes of skipped images (optimise leaves them alone).
    skipped_bytes: u64,
    /// Worst-case (minimum) SSIMULACRA2 across the table's decoded images, for
    /// q90 and q80 full-res. The worst image is what determines whether a
    /// quality level is acceptable for the table, not the average.
    min_q90_ssim: Option<f64>,
    min_q80_ssim: Option<f64>,
    /// Number of images not referenced by any gameitem, table-level field, or
    /// the embedded script. NOTE: only high-confidence when the table has no
    /// external script includes (see `uses_includes`).
    unref_count: usize,
    /// Total stored bytes of unreferenced images: the candidate zero-quality-
    /// loss reclaim from stripping unused images.
    unref_bytes: u64,
    /// Whether the embedded script pulls in external scripts we cannot see. When
    /// true, the unref numbers are low-confidence: an include could use them.
    uses_includes: bool,
}

/// Quality levels swept for the full-resolution lossy candidates, in the order
/// reported (higher quality first, so a reader watches the score degrade
/// left-to-right). The resize tiers use the lower of these.
const QUALITY_HIGH: u32 = 90;
const QUALITY_LOW: u32 = 80;

/// All measured facts for one image. Computed in parallel by `analyze_image`
/// with no shared state, then written sequentially by `survey_table`.
struct ImageRow {
    name: String,
    ext: String,
    detected: String,
    kind: SourceKind,
    is_link: bool,
    transparent: bool,
    decoded: bool,
    /// If set, an optimise pass skips this image (leaves it byte-for-byte
    /// alone); the value is the reason. Covers formats we won't faithfully
    /// round-trip (PSD and other exotics VPX renders via FreeImage) and assets
    /// that break if altered (color-grade LUTs). A normal outcome, not a
    /// failure.
    skipped: Option<&'static str>,
    width: u32,
    height: u32,
    stored: u64,
    lossless_webp: u64,
    /// Candidate matrix (bytes + SSIMULACRA2 at original dims):
    /// q90 full-res, q80 full-res, 50% + q80, 25% + q80.
    q90: Candidate,
    q80: Candidate,
    r50: Candidate,
    r25: Candidate,
    /// Fidelity-preserving optimised size for this image (never > stored).
    lossless_opt: u64,
    /// Lossy-WebP-80 optimised size at full resolution (never > stored).
    lossy_opt: u64,
    decode_error: String,
}

/// Pure per-image analysis: decode, measure candidate encodings, compute the
/// recommended optimised size. Safe to run on many images concurrently.
fn analyze_image(image: &ImageData) -> ImageRow {
    let stored = image.stored_len() as u64;
    let transparent = image_has_transparency(image);
    // Sniff the real content, independent of the (possibly misleading) path
    // extension. Link/screenshot placeholders carry no pixel data.
    let detected = detected_format(image);
    let kind = source_kind(&detected);

    let mut lossless_webp = 0u64;
    let mut q90 = Candidate::default();
    let mut q80 = Candidate::default();
    let mut r50 = Candidate::default();
    let mut r25 = Candidate::default();
    let mut decoded = false;
    let mut decode_error = String::new();

    // Decide up front whether an optimise would ignore this image, from what it
    // IS, not from a failed decode. Two reasons:
    //  - Color-grade LUT (256x16): decodes fine, but the VPinball wiki is
    //    explicit these must never be resized/recompressed or color grading
    //    breaks.
    //  - Exotic format (PSD etc.): VPX renders it via FreeImage, but we won't
    //    faithfully round-trip it, so leave it alone.
    // When skipped we short-circuit: no decode attempt, no re-encode, and
    // crucially no spurious "decode failure" for a format we were never going
    // to touch.
    let skipped: Option<&'static str> = if image.width == 256 && image.height == 16 {
        Some("lut-256x16")
    } else if is_unsupported_format(&detected) {
        Some(skip_reason(&detected))
    } else {
        None
    };

    if skipped.is_none() {
        match image.decode() {
            Ok(Some(dynimg)) => {
                decoded = true;
                // Lossless WebP only makes sense for lossless sources;
                // re-encoding an already-lossy source losslessly inflates it.
                if kind == SourceKind::Lossless {
                    lossless_webp = encode_webp_lossless(&dynimg).unwrap_or(0);
                }
                // Candidate matrix, each with bytes + SSIMULACRA2 vs original.
                // Full-res q90 then q80 (watch the score degrade), then the
                // resize tiers at q80 (scored upscaled-back to original dims).
                q90 = encode_measure(&dynimg, QUALITY_HIGH, 1.0);
                q80 = encode_measure(&dynimg, QUALITY_LOW, 1.0);
                r50 = encode_measure(&dynimg, QUALITY_LOW, 0.5);
                r25 = encode_measure(&dynimg, QUALITY_LOW, 0.25);
            }
            Ok(None) => {
                // Expected for link/screenshot placeholders; anything else is a
                // genuine anomaly (a stream that carried no pixel data at all).
                if !image.is_link() {
                    decode_error = "no pixel data (neither jpeg nor bits)".to_string();
                }
            }
            // A decode error here is genuine: the format is neither exotic (we
            // would have skipped it above) nor a LUT, so it is one we expected
            // to handle. Worth investigating.
            Err(e) => decode_error = e.to_string().replace([',', '\n'], " "),
        }
    }

    // Two optimised figures, both full-resolution and both capped at the
    // current stored size (the "never make it bigger" rule). A skipped image
    // contributes its stored size unchanged to both, since an optimise leaves
    // it byte-for-byte alone.
    //
    // lossless_opt: no quality loss. Only a lossless-source image can shrink
    // (via lossless WebP); a compressed source's lossless-optimal is to leave
    // it untouched.
    //
    // lossy_opt: accept quality-80 lossy WebP where it beats the original.
    let lossless_opt = if skipped.is_none() && decoded && lossless_webp > 0 {
        stored.min(lossless_webp)
    } else {
        stored
    };
    let lossy_opt = if skipped.is_none() && decoded && q80.bytes > 0 {
        stored.min(q80.bytes)
    } else {
        stored
    };

    ImageRow {
        name: image.name.clone(),
        ext: image.ext(),
        detected,
        kind,
        is_link: image.is_link(),
        transparent,
        decoded,
        skipped,
        width: image.width,
        height: image.height,
        stored,
        lossless_webp,
        q90,
        q80,
        r50,
        r25,
        lossless_opt,
        lossy_opt,
        decode_error,
    }
}

fn survey_table(
    table: &Path,
    csv: &mut File,
    failures: &mut File,
    census: &mut FormatCensus,
    sound_census: &mut SoundCensus,
    convention: &HashSet<String>,
) -> Result<TableStats, Box<dyn std::error::Error>> {
    // Read-only. vpx::read opens the file with File::open (no write handle).
    let vpx = vpx::read(table)?;
    let table_str = table.display().to_string();
    let mut stats = TableStats {
        image_count: 0,
        stored: 0,
        lossless_total: 0,
        lossy_total: 0,
        decode_failures: 0,
        skipped_count: 0,
        skipped_bytes: 0,
        min_q90_ssim: None,
        min_q80_ssim: None,
        unref_count: 0,
        unref_bytes: 0,
        uses_includes: false,
    };

    // Build the used-image reference set and lowercased script once per table
    // for orphan detection.
    let used = used_image_names(&vpx);
    let script_lower = vpx.gamedata.code.string.to_lowercase();
    stats.uses_includes = uses_external_includes(&script_lower);

    // Fork-join: the per-image decode + WebP encode work dominates runtime and
    // is independent across images, so run it in parallel. Each image produces
    // an ImageRow with no shared mutable state (temp files are uniquely named
    // via the atomic counter). Rows are then written and folded sequentially so
    // file writes stay single-threaded and output order is deterministic.
    let rows: Vec<ImageRow> = vpx.images.par_iter().map(analyze_image).collect();

    for row in &rows {
        stats.image_count += 1;
        stats.stored += row.stored;
        stats.lossless_total += row.lossless_opt;
        stats.lossy_total += row.lossy_opt;

        // Unreferenced: not a link/screenshot, not in the used set, not named
        // in the embedded script, and not a name referenced by convention in
        // the shared include scripts. Any of these keeps it "used".
        let name_lc = row.name.to_lowercase();
        let unreferenced = !row.is_link
            && !used.contains(&name_lc)
            && !name_in_script(&row.name, &script_lower)
            && !convention.contains(&name_lc);
        if unreferenced {
            stats.unref_count += 1;
            stats.unref_bytes += row.stored;
        }

        if row.skipped.is_some() {
            stats.skipped_count += 1;
            stats.skipped_bytes += row.stored;
        }

        // Track worst-case perceptual quality across the table's images.
        let track_min = |slot: &mut Option<f64>, v: Option<f64>| {
            if let Some(s) = v {
                *slot = Some(slot.map_or(s, |m: f64| m.min(s)));
            }
        };
        track_min(&mut stats.min_q90_ssim, row.q90.ssim2);
        track_min(&mut stats.min_q80_ssim, row.q80.ssim2);

        // Only genuine decode errors go to the failures log. A skipped image
        // (PSD/exotic/LUT) is a normal outcome, not a failure.
        if !row.decode_error.is_empty() {
            stats.decode_failures += 1;
            writeln!(
                failures,
                "{},{},{},{},{},{},{},{}",
                csv_escape(&table_str),
                csv_escape(&row.name),
                row.ext,
                row.detected,
                row.width,
                row.height,
                row.stored,
                csv_escape(&row.decode_error),
            )?;
            failures.flush().ok();
        }

        let census_label = if row.is_link {
            "link/screenshot".to_string()
        } else {
            row.detected.clone()
        };
        census.record(
            &census_label,
            row.stored,
            row.decoded,
            !row.decode_error.is_empty(),
        );

        let ssim = |c: &Candidate| c.ssim2.map(|s| format!("{s:.2}")).unwrap_or_default();
        writeln!(
            csv,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&table_str),
            csv_escape(&row.name),
            row.ext,
            row.detected,
            row.kind.label(),
            row.decoded,
            row.skipped.unwrap_or(""),
            row.is_link,
            unreferenced,
            stats.uses_includes,
            row.transparent,
            row.width,
            row.height,
            row.stored,
            row.lossless_webp,
            row.q90.bytes,
            ssim(&row.q90),
            row.q80.bytes,
            ssim(&row.q80),
            row.r50.bytes,
            ssim(&row.r50),
            row.r25.bytes,
            ssim(&row.r25),
            row.lossless_opt,
            row.lossy_opt,
            csv_escape(&row.decode_error),
        )?;
    }

    // Sounds: verbatim payload, format is the path extension. VPinball (and
    // vpin's sound.rs is_wav) treat a missing extension as wav.
    for sound in &vpx.sounds {
        let stored = sound.data.len() as u64;
        let ext = sound_ext(&sound.path);
        sound_census.record(&ext, stored);
        // Emit a sound row into the same CSV, distinguished by source_kind =
        // "sound" so it is trivially filterable and never confused with an
        // image row.
        writeln!(
            csv,
            "{},{},{},{},sound,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&table_str),
            csv_escape(&sound.name),
            ext,
            format!("sound:{ext}"),
            false,              // decoded
            "",                 // skipped_reason
            false,              // is_link
            false,              // unreferenced (sound orphan detection not done here)
            stats.uses_includes, // table_uses_includes
            false,              // transparent
            0,                  // width
            0,                  // height
            stored,
            "",     // lossless_webp
            "",     // q90_bytes
            "",     // q90_ssim2
            "",     // q80_bytes
            "",     // q80_ssim2
            "",     // r50_bytes
            "",     // r50_ssim2
            "",     // r25_bytes
            "",     // r25_ssim2
            stored, // lossless_opt (unchanged: sound not touched here)
            stored, // lossy_opt (unchanged)
            "",     // decode_error
        )?;
    }

    // Per-table summary row (image_name = "*TOTAL*"). Repurposed columns for
    // this row, mapped onto the shared 21-column layout:
    //   skipped_reason       -> skipped_count
    //   unreferenced         -> unref_count
    //   table_uses_includes  -> uses_includes
    //   transparent          -> skipped_bytes
    //   width                -> unref_bytes (candidate strip reclaim)
    //   stored_bytes         -> total image stored bytes
    //   lossless_opt_bytes   -> lossless_total
    //   lossy_opt_bytes      -> lossy_total
    // Full order (26 cols): table,image_name,path_ext,detected_format,
    // source_kind,decoded,skipped_reason,is_link,unreferenced,
    // table_uses_includes,transparent,width,height,stored_bytes,lossless_webp,
    // q90_bytes,q90_ssim2,q80_bytes,q80_ssim2,r50_bytes,r50_ssim2,r25_bytes,
    // r25_ssim2,lossless_opt,lossy_opt,decode_error
    // Empty run after stored_bytes is 9 columns: lossless_webp + the 8 matrix
    // cols (q90/q80/r50/r25 bytes+ssim2).
    writeln!(
        csv,
        "{},*TOTAL*,,,summary,,{},,{},{},{},{},,{},,,,,,,,,,{},{},",
        csv_escape(&table_str),
        stats.skipped_count,
        stats.unref_count,
        stats.uses_includes,
        stats.skipped_bytes,
        stats.unref_bytes,
        stats.stored,
        stats.lossless_total,
        stats.lossy_total,
    )?;

    Ok(stats)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    /// Uncompressed or losslessly-compressed source (png, bmp, tga, bits). A
    /// lossless WebP re-encode is a genuine no-loss win here.
    Lossless,
    /// Already lossy/compressed source (jpeg, webp, gif) or float HDR/EXR. A
    /// lossless re-encode inflates it; only resize / lossy re-encode helps.
    Compressed,
}

impl SourceKind {
    fn label(self) -> &'static str {
        match self {
            SourceKind::Lossless => "lossless",
            SourceKind::Compressed => "compressed",
        }
    }
}

fn source_kind(detected: &str) -> SourceKind {
    match detected {
        "png" | "bmp" | "bmp/bits" | "tga" => SourceKind::Lossless,
        _ => SourceKind::Compressed, // jpeg, webp, gif, hdr, openexr, psd, dds, ...
    }
}

/// Whether a detected format is one we knowingly cannot decode/re-encode (as
/// opposed to a supported format that failed for another reason). Formats VPX
/// itself does not render (PSD etc.) fall here; such an image is skipped by an
/// optimise rather than treated as a failure.
fn is_unsupported_format(detected: &str) -> bool {
    matches!(detected, "psd" | "dds" | "tiff" | "ico" | "riff")
        || detected.starts_with("unknown-")
}

/// The reason an image in an unsupported format is skipped (left alone). PSD
/// gets its own label since it is the one exotic format we confirmed is
/// actually referenced and rendered by VPX (via FreeImage); the rest are
/// grouped.
fn skip_reason(detected: &str) -> &'static str {
    match detected {
        "psd" => "psd",
        "dds" => "dds",
        "tiff" => "tiff",
        _ => "exotic-format",
    }
}

/// The set of image names (lowercased) referenced anywhere a VPX can point at an
/// image: every gameitem, the table-level GameData image fields, and (as a
/// safety net for dynamic VBScript assignment) any image whose name appears in
/// the script text. Used to detect orphaned images that no runtime path uses.
///
/// This deliberately over-includes rather than under-includes: a false "used"
/// only leaves bloat, a false "orphan" would strip a needed image. The script
/// substring check is the conservative guard for names set dynamically.
fn used_image_names(vpx: &vpin::vpx::VPX) -> HashSet<String> {
    let mut used: HashSet<String> = HashSet::new();
    let mut add = |s: &str| {
        if !s.is_empty() {
            used.insert(s.to_lowercase());
        }
    };

    // Gameitems: reuse the crate's authoritative accessor.
    for item in &vpx.gameitems {
        for name in item.images() {
            add(name);
        }
    }

    // Table-level image references on GameData.
    let gd = &vpx.gamedata;
    add(&gd.image);
    add(&gd.backglass_image_full_desktop);
    add(&gd.backglass_image_full_fullscreen);
    if let Some(s) = &gd.backglass_image_full_single_screen {
        add(s);
    }
    add(&gd.image_color_grade);
    add(&gd.ball_image);
    add(&gd.ball_image_front);
    if let Some(s) = &gd.env_image {
        add(s);
    }

    used
}

/// Load the convention allowlist from the shared VPinball include scripts:
/// every double-quoted string literal across all `.vbs` files in `dir`,
/// lowercased. These are the asset names and dictionary keys that tables may
/// reference only via an include, so treating them as used prevents false
/// "unreferenced" verdicts. Reads the directory non-recursively (shared scripts
/// are flat there).
fn load_convention_names(dir: &Path) -> HashSet<String> {
    let mut set = HashSet::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        eprintln!("Could not read scripts dir {}", dir.display());
        return set;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()).map(|e| e.eq_ignore_ascii_case("vbs"))
            != Some(true)
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for literal in quoted_literals(&text) {
            set.insert(literal.to_lowercase());
        }
    }
    set
}

/// Extract the contents of every double-quoted string literal from VBScript
/// text. VBScript has no escaped quotes inside strings (a doubled "" is an empty
/// string boundary), so a simple alternating split on '"' yields the literals.
fn quoted_literals(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_str = false;
    let mut cur = String::new();
    for ch in text.chars() {
        if ch == '"' {
            if in_str {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                in_str = false;
            } else {
                in_str = true;
            }
        } else if in_str {
            cur.push(ch);
        }
    }
    out
}

/// Whether an image name appears in the VBScript text (lowercased substring),
/// the safety net for images assigned dynamically at runtime.
fn name_in_script(name: &str, script_lower: &str) -> bool {
    !name.is_empty() && script_lower.contains(&name.to_lowercase())
}

/// Whether the embedded script pulls in EXTERNAL scripts we cannot see (e.g.
/// `ExecuteGlobal GetTextFile("controller.vbs")`, `LoadVPM ... "WPC.VBS"`,
/// core.vbs includes). When true, our unreferenced-image verdict is
/// low-confidence: an external include could reference an image we would
/// otherwise call orphaned. The survey reads only the vpx, not the sidecar
/// scripts on disk, so it cannot resolve these.
fn uses_external_includes(script_lower: &str) -> bool {
    const MARKERS: [&str; 5] = ["gettextfile", "executeglobal", "loadvpm", "#include", ".vbs"];
    MARKERS.iter().any(|m| script_lower.contains(m))
}

/// A short label for what an image's bytes actually are. For encoded images we
/// sniff the magic bytes (so a mislabeled .png holding webp is reported as
/// webp). For the LZW bitmap carrier it is "bmp/bits". Falls back to the path
/// extension when there is nothing to sniff.
fn detected_format(image: &vpin::vpx::image::ImageData) -> String {
    if image.is_link() {
        return "link/screenshot".to_string();
    }
    if let Some(jpeg) = image_jpeg_bytes(image) {
        return match image::guess_format(jpeg) {
            Ok(fmt) => format!("{fmt:?}").to_lowercase(),
            // The image crate can't identify it. Fall back to magic-byte
            // sniffing so exotic formats (PSD etc.) are named precisely rather
            // than reported as an opaque "could not determine".
            Err(_) => magic_signature(jpeg, &image.ext()),
        };
    }
    // No encoded bytes means the LZW bitmap carrier.
    "bmp/bits".to_string()
}

/// Identify a format by leading magic bytes, for content the `image` crate does
/// not support. These are formats VPinball may accept but we cannot decode/
/// re-encode; naming them turns "unknown" into an actionable census category.
fn magic_signature(data: &[u8], path_ext: &str) -> String {
    let starts = |m: &[u8]| data.len() >= m.len() && &data[..m.len()] == m;
    if starts(b"8BPS") {
        "psd".to_string()
    } else if starts(b"DDS ") {
        "dds".to_string()
    } else if starts(b"II*\0") || starts(b"MM\0*") {
        "tiff".to_string()
    } else if starts(&[0x00, 0x00, 0x01, 0x00]) {
        "ico".to_string()
    } else if starts(b"RIFF") {
        "riff".to_string()
    } else {
        // Truly unknown: record the path extension and leading bytes so the
        // census row is a followable lead.
        let n = data.len().min(4);
        let hex: Vec<String> = data[..n].iter().map(|b| format!("{b:02x}")).collect();
        format!("unknown-{}({})", path_ext.to_lowercase(), hex.join(""))
    }
}

/// Format label for a sound, from its path extension. Matches vpin/VPinball's
/// rule that a missing extension is treated as wav.
fn sound_ext(path: &str) -> String {
    match Path::new(path).extension().and_then(|e| e.to_str()) {
        Some(e) if !e.is_empty() => e.to_lowercase(),
        _ => "wav".to_string(),
    }
}

/// The encoded byte slice for a `jpeg`-carried image, if present. Returns None
/// for bitmap (`bits`) or empty images. Kept here rather than exposing raw
/// bytes on the public type, since the survey is the only caller that needs the
/// undecoded bytes for sniffing.
fn image_jpeg_bytes(image: &vpin::vpx::image::ImageData) -> Option<&[u8]> {
    // decode() proves whether it is jpeg-carried; but to sniff we need the raw
    // bytes. The public ImageData exposes jpeg via its field.
    image.jpeg.as_ref().map(|j| j.data.as_slice())
}

fn encode_webp_lossless(img: &DynamicImage) -> Option<u64> {
    let mut buf = Vec::new();
    let mut cursor = Cursor::new(&mut buf);
    // The image crate's WebP encoder is lossless, matching images_to_webp.
    img.write_to(&mut cursor, ImageFormat::WebP).ok()?;
    Some(buf.len() as u64)
}

/// Encodes the image (optionally resized to `ratio` of each dimension) as lossy
/// WebP at [`LOSSY_QUALITY`] using cwebp (libwebp), returning the byte size.
///
/// The image crate's WebP encoder is lossless-only, so the real mobile-case
/// lossy size has to come from libwebp. We hand pixels to cwebp via a temp PNG
/// and read back the encoded size. Temp files live in a local scratch dir and
/// are removed immediately.
/// One measurement of a candidate encoding: the resulting byte size and its
/// SSIMULACRA2 perceptual score against the original, at the ORIGINAL
/// dimensions.
#[derive(Default, Clone, Copy)]
struct Candidate {
    bytes: u64,
    /// SSIMULACRA2 vs the original at full dimensions. For resized candidates
    /// the reconstruction is upscaled back to the original size before scoring,
    /// so the number reflects the fidelity a viewer sees when the smaller
    /// texture is displayed over the same geometry. Conservative: on a small
    /// display the perceived quality is higher than this 1:1 figure.
    ssim2: Option<f64>,
}

/// Encode `img` as lossy WebP at `quality`, optionally downscaling to `ratio`
/// of each dimension first, and measure the resulting size plus a SSIMULACRA2
/// score.
///
/// The score compares the lossy WebP against the LOSSLESS version of the same
/// (possibly resized) image, at that image's dimensions. So it isolates the
/// cost of the lossy compression step alone:
///  - full-res tiers: lossy vs the original (the original is already lossless
///    pixels once decoded), i.e. "how much does q80 hurt this image".
///  - resize tiers: lossy-at-50% vs lossless-at-50%, i.e. "how much does q80
///    hurt the downscaled image", holding the resize constant on both sides.
/// This keeps every tier's score on the same "lossy compression quality" scale
/// and avoids the artificial artifacts an upscale-back would introduce. The
/// resize's own detail loss is a separate concern, judged at apply-time in the
/// real engine.
///
/// SSIMULACRA2 scale: 90+ visually lossless, 85 excellent (indistinguishable in
/// a flip test), 80 very high (indistinguishable side-by-side), 70 high (hard
/// to notice without direct comparison), 50 medium (artifacts visible).
fn encode_measure(img: &DynamicImage, quality: u32, ratio: f32) -> Candidate {
    let full_res = (ratio - 1.0).abs() < f32::EPSILON;
    let target_owned = if full_res {
        None
    } else {
        let nw = ((img.width() as f32 * ratio).round() as u32).max(1);
        let nh = ((img.height() as f32 * ratio).round() as u32).max(1);
        Some(img.resize(nw, nh, FilterType::Lanczos3))
    };
    // The reference for scoring is the target itself (lossless), so the score
    // reflects only the lossy step at that resolution.
    let target = target_owned.as_ref().unwrap_or(img);

    let tmp = std::env::temp_dir();
    let stamp = format!(
        "vpin_survey_{}_{}",
        std::process::id(),
        SCRATCH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let ref_png = tmp.join(format!("{stamp}_ref.png"));
    let webp_path = tmp.join(format!("{stamp}.webp"));
    let dist_png = tmp.join(format!("{stamp}_dist.png"));

    let out = (|| -> Candidate {
        // Lossless reference PNG at the target resolution.
        if target.save_with_format(&ref_png, ImageFormat::Png).is_err() {
            return Candidate::default();
        }
        let status = std::process::Command::new("cwebp")
            .args(["-quiet", "-q", &quality.to_string()])
            .arg(&ref_png)
            .arg("-o")
            .arg(&webp_path)
            .status();
        if !matches!(status, Ok(s) if s.success()) {
            return Candidate::default();
        }
        let bytes = std::fs::metadata(&webp_path).map(|m| m.len()).unwrap_or(0);

        // Decode the lossy WebP back and score it against the lossless
        // reference at the same dimensions.
        let ssim2 = (|| -> Option<f64> {
            let webp_bytes = std::fs::read(&webp_path).ok()?;
            let recon = image::load_from_memory(&webp_bytes).ok()?;
            recon.save_with_format(&dist_png, ImageFormat::Png).ok()?;
            ssimulacra2_score(&ref_png, &dist_png)
        })();

        Candidate { bytes, ssim2 }
    })();

    for p in [&ref_png, &webp_path, &dist_png] {
        let _ = std::fs::remove_file(p);
    }
    out
}

/// Run ssimulacra2(original.png, distorted.png) and parse the score.
fn ssimulacra2_score(orig_png: &Path, dist_png: &Path) -> Option<f64> {
    let out = std::process::Command::new("ssimulacra2")
        .arg(orig_png)
        .arg(dist_png)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    s.trim().lines().next()?.trim().parse::<f64>().ok()
}

static SCRATCH_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Local wall-clock timestamp (HH:MM:SS) for log lines. Shells out to `date`,
/// which is trivial next to the per-table encode/score work and avoids pulling
/// in a datetime crate just for logging. Falls back to empty on failure.
fn timestamp() -> String {
    std::process::Command::new("date")
        .arg("+%H:%M:%S")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Worst-case perceptual quality note for a table's log line: the minimum
/// SSIMULACRA2 across its images at q90 and q80. Low numbers flag tables with
/// quality-sensitive images that lossy compression would visibly degrade.
/// Empty when the table has no decoded images to score.
fn ssim_note(stats: &TableStats) -> String {
    match (stats.min_q90_ssim, stats.min_q80_ssim) {
        (Some(q90), Some(q80)) => format!(" | worst ssim2 q90 {q90:.0}/q80 {q80:.0}"),
        _ => String::new(),
    }
}

fn pct_saved(before: u64, after: u64) -> f64 {
    if before == 0 {
        return 0.0;
    }
    100.0 * (before as f64 - after as f64) / before as f64
}

/// Enumerate <root>/<Name>/<Name>.vpx one level deep, sorted. The vpx always
/// shares its parent folder's name, so we build the path directly instead of
/// scanning subtrees.
fn enumerate_tables(root: &Path) -> Vec<PathBuf> {
    let mut tables = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            if let Some(name) = dir.file_name().and_then(|s| s.to_str()) {
                let vpx = dir.join(format!("{name}.vpx"));
                if vpx.is_file() {
                    tables.push(vpx);
                }
            }
        }
    }
    tables.sort();
    tables
}

fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Spawn `caffeinate -imsu -w <pid>` so system/disk sleep is prevented while we
/// run, and re-enabled automatically when the child is killed on drop. Returns
/// a guard that kills the child on drop. If caffeinate is unavailable, returns a
/// no-op guard.
///
/// Note: `-d` is intentionally omitted so the DISPLAY may still sleep during a
/// long run (screen off, system awake). The lid must stay open, since closing
/// it triggers clamshell sleep that caffeinate does not override.
fn spawn_caffeinate() -> CaffeinateGuard {
    let pid = std::process::id();
    match std::process::Command::new("caffeinate")
        .args(["-imsu", "-w", &pid.to_string()])
        .spawn()
    {
        Ok(child) => {
            println!("caffeinate: system awake (display may sleep); keep the lid open");
            CaffeinateGuard(Some(child))
        }
        Err(_) => {
            eprintln!("caffeinate not available; relying on external power settings");
            CaffeinateGuard(None)
        }
    }
}

struct CaffeinateGuard(Option<std::process::Child>);

impl Drop for CaffeinateGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// Round-trips a `.vpx` through vpin's in-memory read + write, producing a new
// file written entirely by this crate. Pair it with the stream_layout example
// to measure whether vpin's writer produces a forward-ordered layout.
//
// Usage:
//   cargo run --release --example roundtrip -- <input.vpx> <output.vpx>

use std::env;
use std::path::PathBuf;
use vpin::vpx;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <input.vpx> <output.vpx>", args[0]);
        std::process::exit(1);
    }
    let input = PathBuf::from(&args[1]);
    let output = PathBuf::from(&args[2]);

    let vpx = vpx::read(&input)?;
    vpx::write(&output, &vpx)?;
    println!("Round-tripped {} -> {}", input.display(), output.display());
    Ok(())
}

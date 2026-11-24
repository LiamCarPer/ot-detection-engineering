//! Decode-throughput microbenchmark for the OT protocol decoders.
//!
//! Each iteration decodes every committed example frame for one protocol. The
//! harness records per-iteration latency, then reports p50, p99, throughput and
//! peak RSS as JSON lines. It is deliberately dependency-free so the benchmark
//! does not change the build graph it is measuring.
//!
//! Run with:
//!     cargo run --release -p ot-perf -- --iterations 10000

use std::hint::black_box;
use std::path::PathBuf;
use std::time::Instant;

const WARMUP_ITERATIONS: u32 = 100;

fn hex_bytes(line: &str) -> Vec<u8> {
    let clean: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    (0..clean.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&clean[index..index + 2], 16).unwrap_or(0))
        .collect()
}

fn read_frames(path: &PathBuf) -> Vec<Vec<u8>> {
    std::fs::read_to_string(path)
        .expect("read example frames")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(hex_bytes)
        .collect()
}

fn peak_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

fn report(protocol: &str, frames: usize, iterations: u32, mut durations: Vec<u64>) {
    durations.sort_unstable();
    let total_frames = frames as u64 * iterations as u64;
    let elapsed_seconds = durations.iter().sum::<u64>() as f64 / 1_000_000_000.0;
    let p50 = durations[durations.len() / 2];
    let p99 = durations[(durations.len() * 99) / 100];
    let p50_per_frame = p50 / frames as u64;
    let p99_per_frame = p99 / frames as u64;
    let rss = match peak_rss_kb() {
        Some(value) => value.to_string(),
        None => "null".to_string(),
    };
    println!(
        "{{\"protocol\":\"{protocol}\",\"frames_per_iteration\":{frames},\
         \"iterations\":{iterations},\"total_frames\":{total_frames},\
         \"elapsed_seconds\":{elapsed_seconds:.6},\
         \"frames_per_second\":{:.2},\"p50_ns\":{p50},\"p99_ns\":{p99},\
         \"p50_ns_per_frame\":{p50_per_frame},\
         \"p99_ns_per_frame\":{p99_per_frame},\
         \"peak_rss_kb\":{rss}}}",
        total_frames as f64 / elapsed_seconds
    );
}

fn bench<F>(protocol: &str, frames: &[Vec<u8>], iterations: u32, mut decode: F)
where
    F: FnMut(&[u8]),
{
    for _ in 0..WARMUP_ITERATIONS {
        for frame in frames {
            decode(black_box(frame));
        }
    }

    let mut durations = Vec::with_capacity(iterations as usize);
    for _ in 0..iterations {
        let started = Instant::now();
        for frame in frames {
            decode(black_box(frame));
        }
        durations.push(started.elapsed().as_nanos() as u64);
    }
    report(protocol, frames.len(), iterations, durations);
}

fn main() {
    let mut iterations = 10_000u32;
    let args: Vec<String> = std::env::args().collect();
    if let Some(index) = args.iter().position(|arg| arg == "--iterations") {
        iterations = args
            .get(index + 1)
            .and_then(|value| value.parse().ok())
            .unwrap_or(iterations);
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let dnp3 = read_frames(&root.join("dnp3-dpi/examples/frames.hex"));
    let s7 = read_frames(&root.join("s7comm-dpi/examples/frames.hex"));
    let opcua = read_frames(&root.join("opcua-dpi/examples/frames.hex"));

    bench("dnp3", &dnp3, iterations, |frame| {
        black_box(dnp3_dpi::parse_stream(black_box(frame)));
    });
    bench("s7comm", &s7, iterations, |frame| {
        black_box(s7comm_dpi::parse_stream(black_box(frame)));
    });
    bench("opcua", &opcua, iterations, |frame| {
        black_box(opcua_dpi::parse_stream(black_box(frame)));
    });
}

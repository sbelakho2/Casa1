//! Windowed presentation capture for the performance gate.
//!
//! Creates a real CAMetalLayer window, renders and presents the requested
//! number of frames, and prints the measured GPU/present JSON. If the host has
//! no display session the command fails with the exact unavailable reason
//! instead of fabricating timestamps.
//!
//! Usage: `casa1-perf-present [frames]`

fn main() {
    let frames = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(120);
    match casa1::perf::measure_gpu_present_windowed(frames) {
        Ok(summary) => match serde_json::to_string_pretty(&summary) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("failed to encode present summary: {error}");
                std::process::exit(2);
            }
        },
        Err(error) => {
            eprintln!("windowed presentation unavailable: {error}");
            std::process::exit(3);
        }
    }
}

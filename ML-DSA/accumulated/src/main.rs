use clap::{Parser, ValueEnum};
use libcrux_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::io::Write;
use std::time::Instant;
use rayon::prelude::*;

#[derive(Parser)]
#[command(name = "ml-dsa-accumulated")]
#[command(about = "Generate accumulated test vectors for ML-DSA", long_about = None)]
struct Cli {
    /// Number of iterations
    #[arg(short, long)]
    iterations: usize,

    /// ML-DSA parameter set
    #[arg(short, long, value_enum)]
    params: MLDSAParams,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum MLDSAParams {
    #[value(name = "44")]
    MLDSA44,
    #[value(name = "65")]
    MLDSA65,
    #[value(name = "87")]
    MLDSA87,
}

fn main() {
    let cli = Cli::parse();

    // Initialize SHAKE128 for input generation
    let mut shake_source = Shake128::default().finalize_xof();

    // Initialize SHAKE128 as accumulator
    let mut accumulator = Shake128::default();

    println!("Generating accumulated test vectors for ML-DSA-{}",
             match cli.params {
                 MLDSAParams::MLDSA44 => "44",
                 MLDSAParams::MLDSA65 => "65",
                 MLDSAParams::MLDSA87 => "87",
             });
    println!("Iterations: {}", cli.iterations);

    let start_time = Instant::now();
    let mut last_checkpoint = start_time;
    let mut processed = 0;

    const BATCH_SIZE: usize = 20;

    while processed < cli.iterations {
        // Determine how many to process in this batch
        let batch_end = std::cmp::min(processed + BATCH_SIZE, cli.iterations);
        let batch_count = batch_end - processed;

        // Read seeds for this batch
        let mut seeds = Vec::with_capacity(batch_count);
        for _ in 0..batch_count {
            let mut seed = [0u8; 32];
            shake_source.read(&mut seed);
            seeds.push(seed);
        }

        // Process batch in parallel and collect results in order
        let results: Vec<(Vec<u8>, Vec<u8>)> = seeds
            .par_iter()
            .map(|&seed| process_iteration_collect(seed, cli.params))
            .collect();

        // Accumulate results in order
        for (public_key, signature) in results {
            accumulator.update(&public_key);
            accumulator.update(&signature);
        }

        processed = batch_end;

        // Update progress display
        if processed % 10000 == 0 && processed > 0 {
            let now = Instant::now();
            let elapsed_since_checkpoint = now - last_checkpoint;
            let total_elapsed = now - start_time;

            // Calculate rate and estimate remaining time
            let iterations_remaining = cli.iterations - processed;
            let iterations_per_second = 10000.0 / elapsed_since_checkpoint.as_secs_f64();
            let estimated_seconds_remaining = iterations_remaining as f64 / iterations_per_second;

            let percentage = (processed as f64 / cli.iterations as f64) * 100.0;

            // Clear line and print progress on single line
            print!("\r{:120}", " "); // Clear with spaces
            print!("\rProgress: {:.1}% ({}/{}) | Elapsed: {} | Rate: {:.0} it/s | ETA: {}",
                   percentage, processed, cli.iterations,
                   format_duration(total_elapsed.as_secs()),
                   iterations_per_second,
                   format_duration(estimated_seconds_remaining as u64));
            std::io::stdout().flush().unwrap();

            last_checkpoint = now;
        }
    }

    // Get final hash from SHAKE128 (32 bytes)
    let mut result = [0u8; 32];
    let mut accumulator_reader = accumulator.finalize_xof();
    accumulator_reader.read(&mut result);

    // Clear the progress line and print completion
    print!("\r{:120}", " "); // Clear line
    let final_duration = start_time.elapsed();
    println!("\rCompleted {} iterations in {}", cli.iterations, format_duration(final_duration.as_secs()));
    println!("Accumulated hash: {}", hex::encode(result));
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

fn process_iteration_collect(
    seed: [u8; 32],
    params: MLDSAParams,
) -> (Vec<u8>, Vec<u8>) {
    // Sign empty message deterministically
    let empty_message = &[];
    let context = &[];  // Empty context
    let randomness = [0u8; 32];

    match params {
        MLDSAParams::MLDSA44 => {
            let kp = ml_dsa_44::generate_key_pair(seed);
            let signature = ml_dsa_44::sign(&kp.signing_key, empty_message, context, randomness).unwrap();
            (kp.verification_key.as_ref().to_vec(), signature.as_ref().to_vec())
        }
        MLDSAParams::MLDSA65 => {
            let kp = ml_dsa_65::generate_key_pair(seed);
            let signature = ml_dsa_65::sign(&kp.signing_key, empty_message, context, randomness).unwrap();
            (kp.verification_key.as_ref().to_vec(), signature.as_ref().to_vec())
        }
        MLDSAParams::MLDSA87 => {
            let kp = ml_dsa_87::generate_key_pair(seed);
            let signature = ml_dsa_87::sign(&kp.signing_key, empty_message, context, randomness).unwrap();
            (kp.verification_key.as_ref().to_vec(), signature.as_ref().to_vec())
        }
    }
}

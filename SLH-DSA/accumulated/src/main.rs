use clap::{Parser, ValueEnum};
use signature::Keypair;
use slh_dsa::*;
use sha3::Shake128;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::io::Write;
use std::time::Instant;
use rayon::prelude::*;

#[derive(Parser)]
#[command(name = "slh-dsa-accumulated")]
#[command(about = "Generate accumulated test vectors for SLH-DSA", long_about = None)]
struct Cli {
    /// Number of iterations
    #[arg(short, long)]
    iterations: usize,

    /// SLH-DSA parameter set
    #[arg(short, long, value_enum)]
    params: SLHDSAParams,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SLHDSAParams {
    #[value(name = "SHA2-128s")]
    SLHDSASHA2128S,
    #[value(name = "SHAKE-128s")]
    SLHDSASHAKE128S,
    #[value(name = "SHA2-128f")]
    SLHDSASHA2128F,
    #[value(name = "SHAKE-128f")]
    SLHDSASHAKE128F,
    #[value(name = "SHA2-192s")]
    SLHDSASHA2192S,
    #[value(name = "SHAKE-192s")]
    SLHDSASHAKE192S,
    #[value(name = "SHA2-192f")]
    SLHDSASHA2192F,
    #[value(name = "SHAKE-192f")]
    SLHDSASHAKE192F,
    #[value(name = "SHA2-256s")]
    SLHDSASHA2256S,
    #[value(name = "SHAKE-256s")]
    SLHDSASHAKE256S,
    #[value(name = "SHA2-256f")]
    SLHDSASHA2256F,
    #[value(name = "SHAKE-256f")]
    SLHDSASHAKE256F,
}

impl SLHDSAParams {
    fn get_security_param(self) -> usize {
        match self {
            SLHDSAParams::SLHDSASHA2128S | SLHDSAParams::SLHDSASHA2128F | SLHDSAParams::SLHDSASHAKE128S | SLHDSAParams::SLHDSASHAKE128F => 16,
            SLHDSAParams::SLHDSASHA2192S | SLHDSAParams::SLHDSASHA2192F | SLHDSAParams::SLHDSASHAKE192S | SLHDSAParams::SLHDSASHAKE192F => 24,
            SLHDSAParams::SLHDSASHA2256S | SLHDSAParams::SLHDSASHA2256F | SLHDSAParams::SLHDSASHAKE256S | SLHDSAParams::SLHDSASHAKE256F => 32,
        } 
    }
}

fn main() {
    let cli = Cli::parse();

    // Initialize SHAKE128 for input generation
    let mut shake_source = Shake128::default().finalize_xof();

    // Initialize SHAKE128 as accumulator
    let mut accumulator = Shake128::default();

    println!("Generating accumulated test vectors for SLH-DSA-{}",
             match cli.params {
                 SLHDSAParams::SLHDSASHA2128S => "SHA2-128s",
                 SLHDSAParams::SLHDSASHAKE128S => "SHAKE-128s",
                 SLHDSAParams::SLHDSASHA2128F => "SHA2-128f",
                 SLHDSAParams::SLHDSASHAKE128F => "SHAKE-128f",
                 SLHDSAParams::SLHDSASHA2192S => "SHA2-192s",
                 SLHDSAParams::SLHDSASHAKE192S => "SHAKE-192s",
                 SLHDSAParams::SLHDSASHA2192F => "SHA2-192f",
                 SLHDSAParams::SLHDSASHAKE192F => "SHAKE-192f",
                 SLHDSAParams::SLHDSASHA2256S => "SHA2-256s",
                 SLHDSAParams::SLHDSASHAKE256S => "SHAKE-256s",
                 SLHDSAParams::SLHDSASHA2256F => "SHA2-256f",
                 SLHDSAParams::SLHDSASHAKE256F => "SHAKE-256f",
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
            let mut seed = vec![0u8; cli.params.get_security_param()*3];
            shake_source.read(&mut seed);
            seeds.push(seed);
        }

        // Process batch in parallel and collect results in order
        let results: Vec<(Vec<u8>, Vec<u8>)> = seeds
            .par_iter()
            .map(|seed| process_iteration_collect(seed, cli.params))
            .collect();

        // Accumulate results in order
        for (public_key, signature) in results {
            accumulator.update(&public_key);
            accumulator.update(&signature);
        }

        processed = batch_end;

        // Update progress display
        if processed % 100 == 0 && processed > 0 {
            let now = Instant::now();
            let elapsed_since_checkpoint = now - last_checkpoint;
            let total_elapsed = now - start_time;

            // Calculate rate and estimate remaining time
            let iterations_remaining = cli.iterations - processed;
            let iterations_per_second = 100.0 / elapsed_since_checkpoint.as_secs_f64();
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

macro_rules! parameter_case {
    ($param:ident, $len:expr, $seed:ident) => {{
        // Sign empty message deterministically
        let empty_message = &[0u8; 0];
        let empty_context = &[0u8; 0];
        let secret_key = slh_dsa::SigningKey::<slh_dsa::$param>::slh_keygen_internal(&$seed[0..$len], &$seed[$len..2*$len], &$seed[2*$len..3*$len]);
        let signature = secret_key.try_sign_with_context(empty_message, empty_context, None).unwrap().to_bytes();
        let public_key = secret_key.verifying_key().to_bytes();
        if !slh_dsa::VerifyingKey::<slh_dsa::$param>::from(public_key).try_verify_with_context(empty_message, empty_context, &slh_dsa::Signature::<slh_dsa::$param>::from(&signature)).is_ok() {
            panic!("Failed verification!");
        }
        (public_key.to_vec(), signature.to_vec())
    }};
}

fn process_iteration_collect(
    seed: &Vec<u8>,
    params: SLHDSAParams,
) -> (Vec<u8>, Vec<u8>) {
    match params {
        SLHDSAParams::SLHDSASHA2128S => parameter_case!(Sha2_128s, 16, seed),
        SLHDSAParams::SLHDSASHAKE128S => parameter_case!(Shake128s, 16, seed),
        SLHDSAParams::SLHDSASHA2128F => parameter_case!(Sha2_128f, 16, seed),
        SLHDSAParams::SLHDSASHAKE128F => parameter_case!(Shake128f, 16, seed),
        SLHDSAParams::SLHDSASHA2192S => parameter_case!(Sha2_192s, 24, seed),
        SLHDSAParams::SLHDSASHAKE192S => parameter_case!(Shake192s, 24, seed),
        SLHDSAParams::SLHDSASHA2192F => parameter_case!(Sha2_192f, 24, seed),
        SLHDSAParams::SLHDSASHAKE192F => parameter_case!(Shake192f, 24, seed),
        SLHDSAParams::SLHDSASHA2256S => parameter_case!(Sha2_256s, 32, seed),
        SLHDSAParams::SLHDSASHAKE256S => parameter_case!(Shake256s, 32, seed),
        SLHDSAParams::SLHDSASHA2256F => parameter_case!(Sha2_256f, 32, seed),
        SLHDSAParams::SLHDSASHAKE256F => parameter_case!(Shake256f, 32, seed),
    }
}

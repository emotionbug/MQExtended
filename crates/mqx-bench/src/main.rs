use std::{
    error,
    fs::File,
    io::{self, BufWriter, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use clap::{Args, Parser, Subcommand};
use mqx_bench::{
    Comparison, ComparisonOptions, Load, Pattern, Quality, Storm, compare, load, storm,
};
use serde::Serialize;

#[derive(Parser)]
#[command(about = "Generate MQTT 3.1.1 load or compare local broker builds")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Publish messages and measure application deliveries after QoS handshakes.
    Load {
        #[command(flatten)]
        endpoints: Endpoints,
        #[command(flatten)]
        traffic: Traffic,
        #[arg(long, value_enum)]
        pattern: Pattern,
        #[command(flatten)]
        shape: Shape,
    },
    /// Reconnect stable client IDs at a target aggregate attempt rate.
    Storm {
        #[command(flatten)]
        endpoints: Endpoints,
        #[arg(long)]
        rate: u64,
        /// Number of reusable client IDs; at most one attempt at a time per ID.
        #[arg(long, default_value_t = 100)]
        clients: usize,
        #[arg(long, default_value_t = 30)]
        seconds: u64,
        #[arg(long)]
        persistent: bool,
    },
    /// Start each broker and run the standard matrix, or one workload with --pattern.
    Compare {
        #[command(flatten)]
        traffic: Traffic,
        #[arg(long, value_enum)]
        pattern: Option<Pattern>,
        #[command(flatten)]
        shape: Shape,
        /// Existing directory on the filesystem to use for cluster WALs.
        #[arg(long, default_value = ".")]
        state_dir: PathBuf,
        /// Tokio runtime workers per MQExtended process.
        #[arg(long, default_value_t = 2)]
        broker_workers: usize,
        #[arg(long, default_value = "mqx-bench-results.json")]
        json: PathBuf,
    },
}

#[derive(Args)]
struct Endpoints {
    /// Listener address. Repeat to spread clients across multiple nodes.
    #[arg(long, default_value = "127.0.0.1:1883")]
    endpoint: Vec<SocketAddr>,
}

#[derive(Args)]
struct Shape {
    #[arg(long, requires = "pattern")]
    publishers: Option<usize>,
    #[arg(long, requires = "pattern")]
    subscribers: Option<usize>,
    #[arg(long, value_enum, requires = "pattern")]
    qos: Option<Quality>,
}

impl Shape {
    fn workload(self, traffic: &Traffic, pattern: Pattern) -> Load {
        let one_to_one = matches!(pattern, Pattern::OneToOne);
        let publishers = self
            .publishers
            .or(if one_to_one { self.subscribers } else { None })
            .unwrap_or(1);
        let subscribers = self
            .subscribers
            .unwrap_or(if one_to_one { publishers } else { 1 });
        traffic.workload(
            pattern,
            publishers,
            subscribers,
            self.qos.unwrap_or(Quality::Qos1),
        )
    }
}

#[derive(Args)]
struct Traffic {
    /// Aggregate publishes per second. Omit for max-throughput mode.
    #[arg(long)]
    rate: Option<u64>,
    /// Fail after reporting if p99 misses this bound, <99% of the rate is sent,
    /// or a delivery or acknowledgement is missing or duplicated.
    #[arg(long, requires = "rate", value_parser = clap::value_parser!(u64).range(1..))]
    require_p99_below_ms: Option<u64>,
    #[arg(long, default_value_t = 30)]
    seconds: u64,
    #[arg(long, default_value_t = 2)]
    drain_seconds: u64,
    #[arg(long, default_value_t = 256)]
    payload_bytes: usize,
    #[arg(long)]
    persistent: bool,
    /// Per-publisher maximum number of outstanding QoS 1/2 handshakes.
    #[arg(long, default_value_t = 20)]
    inflight: u16,
}

impl Traffic {
    fn workload(
        &self,
        pattern: Pattern,
        publishers: usize,
        subscribers: usize,
        qos: Quality,
    ) -> Load {
        Load {
            publishers,
            subscribers,
            pattern,
            qos,
            payload_bytes: self.payload_bytes,
            rate: self.rate,
            duration: Duration::from_secs(self.seconds),
            drain: Duration::from_secs(self.drain_seconds),
            clean_session: !self.persistent,
            inflight: self.inflight,
        }
    }

    fn standard_matrix(&self) -> Vec<Load> {
        [
            (Pattern::FanIn, 100, 1),
            (Pattern::FanOut, 1, 100),
            (Pattern::OneToOne, 200, 200),
        ]
        .into_iter()
        .flat_map(|(pattern, publishers, subscribers)| {
            [Quality::Qos0, Quality::Qos1]
                .map(|qos| self.workload(pattern, publishers, subscribers, qos))
        })
        .collect()
    }

    fn qualify(&self, result: &mqx_bench::LoadResult) -> Result<(), String> {
        let Some(limit) = self.require_p99_below_ms else {
            return Ok(());
        };
        let requested =
            u128::from(self.rate.expect("clap requires --rate")) * u128::from(self.seconds);
        let rate_ok = u128::from(result.published) >= requested - requested / 100;
        if rate_ok
            && result.lost == 0
            && result.duplicates == 0
            && result
                .acknowledged
                .is_none_or(|count| count == result.published)
            && result
                .delivery_latency
                .p99_ns
                .is_some_and(|ns| u128::from(ns) < u128::from(limit) * 1_000_000)
        {
            return Ok(());
        }
        Err(format!(
            "qualification failed: published {}/{requested}, acked {:?}, lost {}, duplicates {}, p99 {:?} ns (required < {limit} ms)",
            result.published,
            result.acknowledged,
            result.lost,
            result.duplicates,
            result.delivery_latency.p99_ns
        ))
    }
}

#[derive(Serialize)]
struct Report<'a> {
    cluster_peer_transport: &'static str,
    broker_workers: usize,
    state_dir: &'a Path,
    results: &'a [Comparison],
}

fn print_table(out: &mut impl Write, rows: &[Comparison]) -> io::Result<()> {
    writeln!(
        out,
        "| Broker | Pattern | Publishers → subscribers | QoS | Publish/s | Deliver/s | P50 ms | P95 ms | P99 ms | Lost | Duplicates | Connect/s |"
    )?;
    writeln!(
        out,
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"
    )?;
    for row in rows {
        let workload = &row.workload;
        let result = &row.result;
        let latency = &result.delivery_latency;
        let fmt = |ns: Option<u64>| {
            ns.map_or_else(|| "—".to_owned(), |ns| format!("{:.3}", ns as f64 / 1e6))
        };
        let pattern = clap::ValueEnum::to_possible_value(&workload.pattern).unwrap();
        let qos = clap::ValueEnum::to_possible_value(&workload.qos).unwrap();
        writeln!(
            out,
            "| {} | {} | {} → {} | {} | {:.0} | {:.0} | {} | {} | {} | {} | {} | {:.0} |",
            row.broker,
            pattern.get_name(),
            workload.publishers,
            workload.subscribers,
            qos.get_name(),
            result.published_per_second,
            result.delivered_per_second,
            fmt(latency.p50_ns),
            fmt(latency.p95_ns),
            fmt(latency.p99_ns),
            result.lost,
            result.duplicates,
            result.connections_per_second
        )?;
    }
    Ok(())
}

fn write_json(
    mut output: impl Write,
    result: &impl Serialize,
) -> Result<(), Box<dyn error::Error>> {
    serde_json::to_writer_pretty(&mut output, result)?;
    writeln!(output)?;
    output.flush()?;
    Ok(())
}

async fn run(command: Command) -> Result<(), Box<dyn error::Error>> {
    match command {
        Command::Load {
            endpoints,
            traffic,
            pattern,
            shape,
        } => {
            let result = load(&endpoints.endpoint, &shape.workload(&traffic, pattern)).await?;
            write_json(io::stdout().lock(), &result)?;
            traffic.qualify(&result)?;
        }
        Command::Storm {
            endpoints,
            rate,
            clients,
            seconds,
            persistent,
        } => {
            let result = storm(
                &endpoints.endpoint,
                &Storm {
                    rate,
                    clients,
                    duration: Duration::from_secs(seconds),
                    clean_session: !persistent,
                },
            )
            .await?;
            write_json(io::stdout().lock(), &result)?;
        }
        Command::Compare {
            traffic,
            pattern,
            shape,
            state_dir,
            broker_workers,
            json,
        } => {
            let options = ComparisonOptions {
                state_dir,
                broker_workers,
            };
            let workloads = match pattern {
                Some(pattern) => vec![shape.workload(&traffic, pattern)],
                None => traffic.standard_matrix(),
            };
            let results = compare(&options, &workloads).await?;
            let report = Report {
                cluster_peer_transport: "mtls",
                broker_workers,
                state_dir: &options.state_dir,
                results: &results,
            };
            write_json(BufWriter::new(File::create(json)?), &report)?;
            print_table(&mut io::stdout().lock(), &results)?;
            for row in &results {
                traffic.qualify(&row.result).map_err(|error| {
                    format!(
                        "{} {:?}/{:?}: {error}",
                        row.broker, row.workload.pattern, row.workload.qos
                    )
                })?;
            }
        }
    }
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> ExitCode {
    let args = Cli::parse();
    let result = tokio::select! {
        result = run(args.command) => result,
        signal = tokio::signal::ctrl_c() => Err(signal.err().unwrap_or_else(|| io::Error::new(io::ErrorKind::Interrupted, "benchmark interrupted")).into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;
use tokio::fs::File;
use crate::errors::RustpenError;
use crate::modules::web_scan::{WebScanner, ModuleScanConfig, OutputFormat, format_scan_result, ModuleScanResult};
use crate::modules::port_scan::ports::HostScanner;
use crate::cores::netscan_en::ScanResult as HostScanResult;

// logging
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "rscan", about = "rscan CLI", version)]
pub struct Cli {
    /// global log level (trace, debug, info, warn, error)
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,

    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Web-related scans
    Web {
        #[command(subcommand)]
        action: WebActions,
    },
    /// Host/port scanning
    Host {
        #[command(subcommand)]
        action: HostActions,
    },
}

#[derive(Subcommand, Debug)]
pub enum HostActions {
    /// TCP port scan
    Tcp {
        /// target host (ip or hostname)
        #[arg(long)]
        host: String,
        /// ports to scan (comma separated or repeated)
        #[arg(long, required = true)]
        ports: Vec<String>,
        /// output format: raw/json
        #[arg(long, default_value = "raw")]
        output: String,
        /// write output to file
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// UDP scan
    Udp {
        #[arg(long)]
        host: String,
        #[arg(long, required = true)]
        ports: Vec<String>,
        #[arg(long, default_value = "raw")]
        output: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// SYN scan
    Syn {
        #[arg(long)]
        host: String,
        #[arg(long, required = true)]
        ports: Vec<String>,
        #[arg(long, default_value = "raw")]
        output: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Quick TCP scan of common ports
    Quick {
        #[arg(long)]
        host: String,
        #[arg(long, default_value = "raw")]
        output: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// ARP scan a CIDR for hosts
    Arp {
        /// CIDR notation, e.g. 192.168.1.0/24
        #[arg(long)]
        cidr: String,
        #[arg(long, default_value = "json")]
        output: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
#[derive(Subcommand, Debug)]
pub enum WebActions {
    /// Directory scan: provide a base URL and one or more paths
    Dir {
        /// base URL (e.g. http://127.0.0.1:8080)
        #[arg(long)]
        base: String,
        /// paths to request (can be provided multiple times)
        #[arg(long, required = true)]
        paths: Vec<String>,
        /// optional output file to stream results to (will write one entry per line)
        #[arg(long)]
        stream_to: Option<PathBuf>,
        /// output format: raw,json,csv
        #[arg(long, default_value = "raw")]
        output: String,
        /// concurrency for module scan
        #[arg(long)]
        concurrency: Option<usize>,
        /// timeout per request in milliseconds
        #[arg(long)]
        timeout_ms: Option<u64>,
        /// max retries per request (module-level override)
        #[arg(long)]
        max_retries: Option<u32>,
        /// override per-host concurrency
        #[arg(long)]
        per_host_concurrency: Option<usize>,
        /// disable deduplication
        #[arg(long, default_value_t = true)]
        dedupe: bool,
        /// minimum status code to include
        #[arg(long)]
        status_min: Option<u16>,
        /// maximum status code to include
        #[arg(long)]
        status_max: Option<u16>,
    },
    /// Fuzz scan: URL template should contain FUZZ
    Fuzz {
        #[arg(long)]
        url: String,
        #[arg(long, required = true)]
        keywords: Vec<String>,
        #[arg(long)]
        stream_to: Option<PathBuf>,
        #[arg(long, default_value = "raw")]
        output: String,
        #[arg(long)]
        concurrency: Option<usize>,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        max_retries: Option<u32>,
        #[arg(long)]
        per_host_concurrency: Option<usize>,
        #[arg(long, default_value_t = true)]
        dedupe: bool,
        #[arg(long)]
        status_min: Option<u16>,
        #[arg(long)]
        status_max: Option<u16>,
    },

    /// Subdomain burst (dns)
    Dns {
        #[arg(long)]
        domain: String,
        #[arg(long, required = true)]
        words: Vec<String>,
        #[arg(long)]
        stream_to: Option<PathBuf>,
        #[arg(long, default_value = "raw")]
        output: String,
        #[arg(long)]
        concurrency: Option<usize>,
        #[arg(long)]
        timeout_ms: Option<u64>,
        #[arg(long)]
        max_retries: Option<u32>,
        #[arg(long)]
        per_host_concurrency: Option<usize>,
        #[arg(long, default_value_t = true)]
        dedupe: bool,
        #[arg(long)]
        status_min: Option<u16>,
        #[arg(long)]
        status_max: Option<u16>,
    },

}

fn parse_output(fmt: &str) -> OutputFormat {
    match fmt.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "csv" => OutputFormat::Csv,
        _ => OutputFormat::Raw,
    }
}

async fn write_lines_to_file(mut file: File, mut rx: tokio::sync::mpsc::Receiver<Result<ModuleScanResult, RustpenError>>, fmt: OutputFormat) -> Result<(), RustpenError> {
    while let Some(r) = rx.recv().await {
        match r {
            Ok(m) => {
                let line = format!("{}\n", format_scan_result(&m, &fmt));
                file.write_all(line.as_bytes()).await.map_err(|e| RustpenError::Io(e))?;
            }
            Err(e) => {
                let line = format!("ERROR: {:?}\n", e);
                file.write_all(line.as_bytes()).await.map_err(|e| RustpenError::Io(e))?;
            }
        }
    }
    Ok(())
}

fn format_host_scan_result(r: &HostScanResult, fmt: &str) -> String {
    match fmt.to_lowercase().as_str() {
        "json" => serde_json::to_string(&r.to_json()).unwrap_or_else(|_| format!("host: {} open: {:?}", r.host, r.open_ports())),
        _ => format!("host={} ip={} proto={} open_ports={:?} duration_ms={} errors={}", r.host, r.ip, format!("{:?}", r.protocol), r.open_ports(), r.scan_duration.as_millis(), r.errors),
    }
}

async fn write_host_output_to_file(mut file: File, s: &str) -> Result<(), RustpenError> {
    file.write_all(format!("{}\n", s).as_bytes()).await.map_err(|e| RustpenError::Io(e))?;
    Ok(())
}

pub async fn run_from_args<I, T>(args: I) -> Result<(), RustpenError>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);

    // initialize tracing according to log_level (ok if already initialized in tests)
    let env_filter = EnvFilter::new(cli.log_level.clone());
    let _ = tracing_subscriber::fmt().with_env_filter(env_filter).try_init();
    info!("Starting rscan, log_level={}", cli.log_level);

    // default WebScanner config
    let ws_cfg = crate::modules::web_scan::WebScanConfig::default();
    let ws = WebScanner::new(ws_cfg)?;

    match cli.cmd {
        Commands::Web { action } => match action {
            WebActions::Dir { base, paths, stream_to, output, concurrency, timeout_ms, max_retries, per_host_concurrency, dedupe, status_min, status_max } => {
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig::default();
                if let Some(c) = concurrency { mcfg.concurrency = c; }
                if let Some(t) = timeout_ms { mcfg.timeout_ms = Some(t); }
                if let Some(r) = max_retries { mcfg.max_retries = Some(r); }
                if let Some(p) = per_host_concurrency { mcfg.per_host_concurrency_override = Some(p); }
                mcfg.dedupe_results = dedupe;
                mcfg.status_min = status_min;
                mcfg.status_max = status_max;

                if let Some(path) = stream_to {
                    let rx = ws.dir_scan_stream(&base, paths, Some(mcfg));
                    let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                    write_lines_to_file(file, rx, fmt).await?;
                } else {
                    let paths_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                    let res = ws.dir_scan(&base, &paths_refs, Some(mcfg)).await?;
                    for r in res { println!("{}", format_scan_result(&r, &fmt)); }
                }
            }
            WebActions::Fuzz { url, keywords, stream_to, output, concurrency, timeout_ms, max_retries, per_host_concurrency, dedupe, status_min, status_max } => {
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig::default();
                if let Some(c) = concurrency { mcfg.concurrency = c; }
                if let Some(t) = timeout_ms { mcfg.timeout_ms = Some(t); }
                if let Some(r) = max_retries { mcfg.max_retries = Some(r); }
                if let Some(p) = per_host_concurrency { mcfg.per_host_concurrency_override = Some(p); }
                mcfg.dedupe_results = dedupe;
                mcfg.status_min = status_min;
                mcfg.status_max = status_max;

                if let Some(path) = stream_to {
                    let rx = ws.fuzz_scan_stream(&url, keywords, Some(mcfg));
                    let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                    write_lines_to_file(file, rx, fmt).await?;
                } else {
                    let kws: Vec<&str> = keywords.iter().map(|s| s.as_str()).collect();
                    let res = ws.fuzz_scan(&url, &kws, Some(mcfg)).await?;
                    for r in res { println!("{}", format_scan_result(&r, &fmt)); }
                }
            }
            WebActions::Dns { domain, words, stream_to, output, concurrency, timeout_ms, max_retries, per_host_concurrency, dedupe, status_min, status_max } => {
                let fmt = parse_output(&output);
                let mut mcfg = ModuleScanConfig::default();
                if let Some(c) = concurrency { mcfg.concurrency = c; }
                if let Some(t) = timeout_ms { mcfg.timeout_ms = Some(t); }
                if let Some(r) = max_retries { mcfg.max_retries = Some(r); }
                if let Some(p) = per_host_concurrency { mcfg.per_host_concurrency_override = Some(p); }
                mcfg.dedupe_results = dedupe;
                mcfg.status_min = status_min;
                mcfg.status_max = status_max;

                if let Some(path) = stream_to {
                    // dns does not have a stream API; run and write lines
                    let res = ws.subdomain_burst(&domain, &words.iter().map(|s| s.as_str()).collect::<Vec<&str>>(), Some(mcfg)).await?;
                    let mut file = File::create(path).await.map_err(|e| RustpenError::Io(e))?;
                    for r in res { let line = format!("{}\n", format_scan_result(&r, &fmt)); file.write_all(line.as_bytes()).await.map_err(|e| RustpenError::Io(e))?; }
                } else {
                    let res = ws.subdomain_burst(&domain, &words.iter().map(|s| s.as_str()).collect::<Vec<&str>>(), Some(mcfg)).await?;
                    for r in res { println!("{}", format_scan_result(&r, &fmt)); }
                }
            }
        },
        Commands::Host { action } => match action {
            HostActions::Tcp { host, ports, output, out } => {
                let scanner = HostScanner::default();
                let mut parsed = Vec::new();
                for p in ports.iter() {
                    for part in p.split(',') { if part.trim().is_empty() { continue } parsed.push(part.trim().parse::<u16>().map_err(|e| RustpenError::ParseError(e.to_string()))?); }
                }
                let res = scanner.scan_tcp(&host, &parsed).await?;
                let s = format_host_scan_result(&res, &output);
                if let Some(path) = out { let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?; write_host_output_to_file(file, &s).await?; } else { println!("{}", s); }
            }
            HostActions::Udp { host, ports, output, out } => {
                // Create a manager with UDP enabled for UDP scans
                use crate::cores::netscan_en::{ScanManager, UdpConfig, TcpConfig};
                let manager = ScanManager::new_with_udp(TcpConfig::default(), Some(UdpConfig::default()));
                let scanner = HostScanner::with_manager(manager);
                let mut parsed = Vec::new();
                for p in ports.iter() { for part in p.split(',') { if part.trim().is_empty() { continue } parsed.push(part.trim().parse::<u16>().map_err(|e| RustpenError::ParseError(e.to_string()))?); } }
                let res = scanner.scan_udp(&host, &parsed).await?;
                let s = format_host_scan_result(&res, &output);
                if let Some(path) = out { let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?; write_host_output_to_file(file, &s).await?; } else { println!("{}", s); }
            }
            HostActions::Syn { host, ports, output, out } => {
                // Create a manager with SYN enabled for SYN scans
                use crate::cores::netscan_en::{ScanManager, TcpConfig, SynConfig};
                let manager = ScanManager::new_with_syn(TcpConfig::default(), Some(SynConfig::default()));
                let scanner = HostScanner::with_manager(manager);
                let mut parsed = Vec::new();
                for p in ports.iter() { for part in p.split(',') { if part.trim().is_empty() { continue } parsed.push(part.trim().parse::<u16>().map_err(|e| RustpenError::ParseError(e.to_string()))?); } }
                let res = scanner.scan_syn(&host, &parsed).await?;
                let s = format_host_scan_result(&res, &output);
                if let Some(path) = out { let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?; write_host_output_to_file(file, &s).await?; } else { println!("{}", s); }
            }
            HostActions::Quick { host, output, out } => {
                let scanner = HostScanner::default();
                let res = scanner.quick_tcp(&host).await?;
                let s = format_host_scan_result(&res, &output);
                if let Some(path) = out { let file = File::create(path).await.map_err(|e| RustpenError::Io(e))?; write_host_output_to_file(file, &s).await?; } else { println!("{}", s); }
            }
            HostActions::Arp { cidr, output, out } => {
                let scanner = HostScanner::default();
                let res = scanner.arp_scan_cidr(&cidr).await?;
                if output.to_lowercase() == "json" {
                    let json_vec: Vec<_> = res.iter().map(|h| serde_json::json!({"ip": h.ip, "mac": h.mac.to_string(), "interface": h.interface})).collect();
                    let s = serde_json::to_string(&json_vec).map_err(|e| RustpenError::ParseError(e.to_string()))?;
                    if let Some(path) = out { let mut file = File::create(path).await.map_err(|e| RustpenError::Io(e))?; file.write_all(format!("{}\n", s).as_bytes()).await.map_err(|e| RustpenError::Io(e))?; } else { println!("{}", s); }
                } else {
                    for h in res { let line = format!("{} {} {}\n", h.ip, h.mac, h.interface); if let Some(path) = &out { let mut file = File::create(path).await.map_err(|e| RustpenError::Io(e))?; file.write_all(line.as_bytes()).await.map_err(|e| RustpenError::Io(e))?; } else { print!("{}", line); } }
                }
            }
        }
    }

    Ok(())
}

/// Run using environment args
pub async fn run() -> Result<(), RustpenError> {
    run_from_args(std::env::args()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, UdpSocket};
    use std::fs;
    use std::env;

    #[tokio::test]
    async fn cli_host_tcp_writes_output_file() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { let _ = listener.accept().await; });

        let tmp = env::temp_dir().join(format!("rscan_cli_tcp_{}.out", port));
        let port_str = port.to_string();
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec!["rscan", "host", "tcp", "--host", "127.0.0.1", "--ports", &port_str, "--output", "json", "--out", &tmp_str];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_host_udp_writes_output_file() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
                let _ = socket.send_to(&buf[..len], &addr).await;
            }
        });

        let tmp = env::temp_dir().join(format!("rscan_cli_udp_{}.out", port));
        let port_str = port.to_string();
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec!["rscan", "host", "udp", "--host", "127.0.0.1", "--ports", &port_str, "--output", "json", "--out", &tmp_str];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_host_syn_writes_output_file() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { let _ = listener.accept().await; });

        let tmp = env::temp_dir().join(format!("rscan_cli_syn_{}.out", port));
        let port_str = port.to_string();
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec!["rscan", "host", "syn", "--host", "127.0.0.1", "--ports", &port_str, "--output", "json", "--out", &tmp_str];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_host_quick_returns_ok() {
        let tmp = env::temp_dir().join("rscan_cli_quick.out");
        let tmp_str = tmp.to_str().unwrap().to_string();
        let args = vec!["rscan", "host", "quick", "--host", "127.0.0.1", "--output", "json", "--out", &tmp_str];
        run_from_args(args).await.unwrap();
        let s = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(s.contains("\"open_ports_count\""));
        let _ = fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn cli_concurrent_run_from_args_initialization_is_safe() {
        use std::ffi::OsString;
        // Spawn two concurrent invocations which both initialize tracing via try_init()
        let tmp1 = env::temp_dir().join("rscan_cli_concur1.out");
        let tmp2 = env::temp_dir().join("rscan_cli_concur2.out");
        let tmp1_os = tmp1.as_os_str().to_os_string();
        let tmp2_os = tmp2.as_os_str().to_os_string();
        let args1: Vec<OsString> = vec!["rscan".into(), "--log-level".into(), "info".into(), "host".into(), "quick".into(), "--host".into(), "127.0.0.1".into(), "--output".into(), "json".into(), "--out".into(), tmp1_os];
        let args2: Vec<OsString> = vec!["rscan".into(), "--log-level".into(), "info".into(), "host".into(), "quick".into(), "--host".into(), "127.0.0.1".into(), "--output".into(), "json".into(), "--out".into(), tmp2_os];
        let j1 = tokio::spawn(async move { run_from_args(args1).await });
        let j2 = tokio::spawn(async move { run_from_args(args2).await });
        let r1 = j1.await.unwrap();
        let r2 = j2.await.unwrap();
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        let _ = fs::remove_file(tmp1);
        let _ = fs::remove_file(tmp2);
    }
}

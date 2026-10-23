use loglens::{analyze_file, Stats};
use std::process::exit;
use std::thread;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("usage: loglens <logfile> [--threads N] [--top N]");
        exit(2);
    }
    let path = &args[1];
    let mut threads = thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
    let mut top = 5usize;
    let mut i = 2;
    while i < args.len() {
        let val = args.get(i + 1).and_then(|v| v.parse::<usize>().ok());
        match (args[i].as_str(), val) {
            ("--threads", Some(n)) if n > 0 => threads = n,
            ("--top", Some(n)) => top = n,
            (flag, _) => {
                eprintln!("bad or incomplete option: {flag}");
                exit(2);
            }
        }
        i += 2;
    }

    let stats = match analyze_file(path, threads) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error reading {path}: {e}");
            exit(1);
        }
    };

    println!("lines: {}  malformed: {}  bytes: {}", stats.lines, stats.malformed, stats.bytes);
    println!("\nstatus codes:");
    let mut statuses: Vec<_> = stats.by_status.iter().collect();
    statuses.sort();
    for (code, n) in statuses {
        println!("  {code}: {n}");
    }
    println!("\ntop paths:");
    for (p, n) in Stats::top(&stats.by_path, top) {
        println!("  {n:>8}  {p}");
    }
    println!("\ntop IPs:");
    for (ip, n) in Stats::top(&stats.by_ip, top) {
        println!("  {n:>8}  {ip}");
    }
}

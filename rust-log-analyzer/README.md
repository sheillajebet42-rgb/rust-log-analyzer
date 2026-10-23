# loglens - parallel access-log analyzer (Rust)
![CI](https://github.com/YOUR_USER/rust-log-analyzer/actions/workflows/ci.yml/badge.svg)

Zero-dependency CLI that parses Common Log Format files in parallel and reports status codes, top paths and top client IPs.

```bash
cargo run --release -- access.log --threads 8 --top 10
```

## How it works
1. The file is split into N byte ranges. Each cut point is moved forward to the next newline, so no line is ever split between workers.
2. Each worker thread reads only its own range and builds a local `Stats`.
3. Partial results are merged on the main thread (map-reduce, no shared locks while counting).

## Design decisions
- **Local aggregation + merge** instead of a shared `Mutex<HashMap>`: no contention in the hot loop.
- **Borrowed parsing** (`Entry<'a>` holds `&str` slices of the line): parsing allocates nothing; strings are copied only when inserting a new key.
- **Lossy UTF-8** so one corrupt byte can't abort a multi-GB analysis; bad lines are counted as `malformed`.
- **Deterministic output**: ties in "top N" are broken by key.
- A property-style test asserts parallel results equal sequential results for 1, 2, 3, 7 and 16 threads.

## Ideas to extend
Memory-mapped input (`memmap2`), time-bucket histograms, percentile latency, streaming mode for stdin.

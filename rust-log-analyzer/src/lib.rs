//! Parsing and aggregation for Common Log Format style access logs.
//!
//! Example line:
//! `203.0.113.5 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326`

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::thread;

#[derive(Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub ip: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub bytes: u64,
}

/// Parse a single log line. Returns `None` for malformed lines.
pub fn parse_line(line: &str) -> Option<Entry<'_>> {
    let ip = line.split_whitespace().next()?;
    let q1 = line.find('"')?;
    let q2 = q1 + 1 + line[q1 + 1..].find('"')?;
    let request = &line[q1 + 1..q2];
    let mut parts = request.split_whitespace();
    let method = parts.next()?;
    let path = parts.next()?;
    let mut rest = line[q2 + 1..].split_whitespace();
    let status: u16 = rest.next()?.parse().ok()?;
    let bytes = match rest.next()? {
        "-" => 0,
        n => n.parse().ok()?,
    };
    Some(Entry { ip, method, path, status, bytes })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub lines: u64,
    pub malformed: u64,
    pub bytes: u64,
    pub by_status: HashMap<u16, u64>,
    pub by_path: HashMap<String, u64>,
    pub by_ip: HashMap<String, u64>,
}

impl Stats {
    pub fn add_line(&mut self, line: &str) {
        if line.trim().is_empty() {
            return;
        }
        self.lines += 1;
        match parse_line(line) {
            Some(e) => {
                self.bytes += e.bytes;
                *self.by_status.entry(e.status).or_insert(0) += 1;
                // Avoid allocating when the key already exists.
                bump(&mut self.by_path, e.path);
                bump(&mut self.by_ip, e.ip);
            }
            None => self.malformed += 1,
        }
    }

    pub fn merge(&mut self, other: Stats) {
        self.lines += other.lines;
        self.malformed += other.malformed;
        self.bytes += other.bytes;
        for (k, v) in other.by_status { *self.by_status.entry(k).or_insert(0) += v; }
        for (k, v) in other.by_path { *self.by_path.entry(k).or_insert(0) += v; }
        for (k, v) in other.by_ip { *self.by_ip.entry(k).or_insert(0) += v; }
    }

    /// Top `n` entries of a count map, sorted by count desc then key asc (deterministic).
    pub fn top<K: Clone + Ord>(map: &HashMap<K, u64>, n: usize) -> Vec<(K, u64)> {
        let mut v: Vec<(K, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }
}

fn bump(map: &mut HashMap<String, u64>, key: &str) {
    if let Some(c) = map.get_mut(key) {
        *c += 1;
    } else {
        map.insert(key.to_string(), 1);
    }
}

pub fn analyze_str(text: &str) -> Stats {
    let mut s = Stats::default();
    for line in text.lines() {
        s.add_line(line);
    }
    s
}

/// Split `[0, len)` into up to `parts` byte ranges whose boundaries sit on line starts.
/// Reads only a few bytes around each cut point, so it is cheap even for huge files.
pub fn chunk_boundaries(file: &mut File, len: u64, parts: usize) -> io::Result<Vec<(u64, u64)>> {
    let parts = parts.max(1) as u64;
    let mut cuts = vec![0u64];
    for i in 1..parts {
        let mut pos = len * i / parts;
        if pos <= *cuts.last().unwrap() {
            continue;
        }
        file.seek(SeekFrom::Start(pos))?;
        let mut buf = [0u8; 4096];
        'find: loop {
            let n = file.read(&mut buf)?;
            if n == 0 {
                pos = len;
                break;
            }
            if let Some(i) = buf[..n].iter().position(|&b| b == b'\n') {
                pos += i as u64 + 1;
                break 'find;
            }
            pos += n as u64;
        }
        if pos < len && pos > *cuts.last().unwrap() {
            cuts.push(pos);
        }
    }
    cuts.push(len);
    Ok(cuts.windows(2).map(|w| (w[0], w[1])).filter(|(a, b)| a < b).collect())
}

/// Analyze a file using `threads` worker threads, each handling its own line-aligned slice.
pub fn analyze_file(path: &str, threads: usize) -> io::Result<Stats> {
    let mut f = File::open(path)?;
    let len = f.metadata()?.len();
    let ranges = chunk_boundaries(&mut f, len, threads)?;

    let handles: Vec<_> = ranges
        .into_iter()
        .map(|(start, end)| {
            let path = path.to_string();
            thread::spawn(move || -> io::Result<Stats> {
                let mut f = File::open(path)?;
                f.seek(SeekFrom::Start(start))?;
                let mut buf = Vec::with_capacity((end - start) as usize);
                f.take(end - start).read_to_end(&mut buf)?;
                // Lossy so a stray invalid byte cannot abort a multi-GB run.
                Ok(analyze_str(&String::from_utf8_lossy(&buf)))
            })
        })
        .collect();

    let mut total = Stats::default();
    for h in handles {
        total.merge(h.join().expect("worker panicked")?);
    }
    Ok(total)
}

use loglens::{analyze_file, analyze_str, parse_line, Stats};
use std::io::Write;

const SAMPLE: &str = r#"203.0.113.5 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326
203.0.113.5 - - [10/Oct/2025:13:55:37 +0000] "GET /about HTTP/1.1" 200 512
198.51.100.7 - - [10/Oct/2025:13:55:38 +0000] "POST /login HTTP/1.1" 401 -
198.51.100.7 - - [10/Oct/2025:13:55:39 +0000] "GET /index.html HTTP/1.1" 304 0
this is not a log line
"#;

#[test]
fn parses_valid_line() {
    let e = parse_line(SAMPLE.lines().next().unwrap()).unwrap();
    assert_eq!((e.ip, e.method, e.path, e.status, e.bytes), ("203.0.113.5", "GET", "/index.html", 200, 2326));
}

#[test]
fn dash_bytes_is_zero_and_garbage_is_none() {
    let e = parse_line(SAMPLE.lines().nth(2).unwrap()).unwrap();
    assert_eq!((e.status, e.bytes), (401, 0));
    assert!(parse_line("garbage").is_none());
    assert!(parse_line(r#"1.1.1.1 "GET""#).is_none());
}

#[test]
fn aggregates() {
    let s = analyze_str(SAMPLE);
    assert_eq!((s.lines, s.malformed, s.bytes), (5, 1, 2838));
    assert_eq!(s.by_status[&200], 2);
    assert_eq!(Stats::top(&s.by_path, 1), vec![("/index.html".to_string(), 2)]);
}

#[test]
fn parallel_matches_sequential_for_any_thread_count() {
    let mut text = String::new();
    for i in 0..5000 {
        text.push_str(&format!(
            "10.0.0.{} - - [x] \"GET /p/{} HTTP/1.1\" {} {}\n",
            i % 50, i % 17, if i % 9 == 0 { 500 } else { 200 }, i % 1000
        ));
    }
    text.push_str("garbage\n");
    let dir = std::env::temp_dir().join("loglens_test.log");
    std::fs::File::create(&dir).unwrap().write_all(text.as_bytes()).unwrap();

    let expected = analyze_str(&text);
    for threads in [1, 2, 3, 7, 16] {
        let got = analyze_file(dir.to_str().unwrap(), threads).unwrap();
        assert_eq!(got, expected, "mismatch with {threads} threads");
    }
}

#[test]
fn empty_file_is_ok() {
    let p = std::env::temp_dir().join("loglens_empty.log");
    std::fs::File::create(&p).unwrap();
    let s = analyze_file(p.to_str().unwrap(), 4).unwrap();
    assert_eq!(s.lines, 0);
}

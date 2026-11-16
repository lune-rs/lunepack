//! Proxy selection through the environment (M4-D14: an environment proxy wins everywhere).
//!
//! The environment of a running test process cannot be changed without `unsafe`, so each case
//! re-runs this binary as a child process whose environment is set on the `Command`; the parent's
//! environment is never touched. This test has its own `main` (see Cargo.toml).

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::panic::catch_unwind;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use lunepack_core::{BlockingTransport, CancelToken, Request};
use lunepack_http::{UreqOptions, UreqTransport, proxy_for_url};

const PROXY_VARS: &[&str] = &[
    "ALL_PROXY",
    "all_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "NO_PROXY",
    "no_proxy",
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--proxy-for") => {
            // The proxy a request to the URL would use, `none` for a direct connection.
            println!(
                "{}",
                proxy_for_url(&args[1]).unwrap_or_else(|| "none".to_owned())
            );
            return;
        }
        Some(mode @ ("--fetch" | "--fetch-with")) => {
            // `--fetch <url>` with the default options; `--fetch-with <direct 0|1>
            // <max_redirects> <url>` with those.
            let (transport, url) = if mode == "--fetch" {
                (UreqTransport::new(), args[1].clone())
            } else {
                let options = UreqOptions {
                    direct: args[1] == "1",
                    max_redirects: args[2].parse().expect("max redirects"),
                    connect_timeout: Duration::from_secs(5),
                    read_timeout: Duration::from_secs(5),
                };
                (UreqTransport::with_options(&options), args[3].clone())
            };
            let request = Request {
                url,
                range: None,
                if_range: None,
            };
            match transport.get(&request, &CancelToken::new()) {
                Ok(mut response) => {
                    let mut body = String::new();
                    response.body.read_to_string(&mut body).expect("body");
                    println!("status={} body={body}", response.head.status);
                }
                Err(e) => println!("error={:?}", e.kind),
            }
            return;
        }
        _ => {}
    }

    let tests: &[(&str, fn())] = &[
        ("an_env_proxy_is_selected", env_proxy_is_selected),
        ("all_proxy_comes_before_https_proxy", all_proxy_first),
        ("no_proxy_bypasses_the_env_proxy", no_proxy_bypasses),
        (
            "a_request_goes_through_the_env_proxy",
            request_goes_through_proxy,
        ),
        ("without_env_there_is_no_proxy_on_linux", no_env_no_proxy),
        (
            "a_direct_transport_ignores_every_env_proxy",
            direct_ignores_env_proxies,
        ),
        (
            "with_no_redirects_a_302_is_returned_and_not_followed",
            no_redirects_returns_the_302,
        ),
    ];
    let mut failed = 0;
    for (name, test) in tests {
        match catch_unwind(*test) {
            Ok(()) => println!("test {name} ... ok"),
            Err(_) => {
                println!("test {name} ... FAILED");
                failed += 1;
            }
        }
    }
    println!(
        "\ntest result: {} passed; {failed} failed",
        tests.len() - failed
    );
    if failed > 0 {
        std::process::exit(1);
    }
}

/// A child of this binary with every proxy variable removed and `env` set.
fn child(env: &[(&str, &str)], args: &[&str]) -> String {
    let mut cmd = Command::new(std::env::current_exe().expect("current exe"));
    cmd.args(args);
    for var in PROXY_VARS {
        cmd.env_remove(var);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("child");
    assert!(
        output.status.success(),
        "child failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .trim()
        .to_owned()
}

const URL: &str = "https://updates.example.invalid/feed";

fn env_proxy_is_selected() {
    for var in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "HTTP_PROXY"] {
        let got = child(&[(var, "http://127.0.0.1:3128")], &["--proxy-for", URL]);
        assert_eq!(got, "127.0.0.1:3128", "{var}");
    }
}

fn all_proxy_first() {
    let got = child(
        &[
            ("HTTPS_PROXY", "http://127.0.0.1:2222"),
            ("ALL_PROXY", "http://127.0.0.1:1111"),
        ],
        &["--proxy-for", URL],
    );
    assert_eq!(got, "127.0.0.1:1111");
}

fn no_proxy_bypasses() {
    let got = child(
        &[
            ("HTTPS_PROXY", "http://127.0.0.1:3128"),
            ("NO_PROXY", "updates.example.invalid"),
        ],
        &["--proxy-for", URL],
    );
    assert_eq!(got, "none");
}

/// Reads up to the end of one request head; returns it.
fn read_head(stream: &mut std::net::TcpStream) -> String {
    let mut seen = Vec::new();
    let mut buf = [0u8; 1024];
    while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut buf).expect("read");
        assert!(n > 0, "closed early");
        seen.extend_from_slice(&buf[..n]);
    }
    String::from_utf8_lossy(&seen).into_owned()
}

/// A CONNECT proxy that records what it is asked for, tunnels nothing and answers the request
/// inside the tunnel itself with `200 ok`.
fn request_goes_through_proxy() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let connect = read_head(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .expect("write");
        let inner = read_head(&mut stream);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write");
        (
            connect.lines().next().unwrap_or_default().to_owned(),
            inner.lines().next().unwrap_or_default().to_owned(),
        )
    });
    let proxy = format!("http://127.0.0.1:{port}");
    // The host never resolves: only a proxy can answer.
    let got = child(
        &[("HTTP_PROXY", proxy.as_str())],
        &["--fetch", "http://updates.example.invalid/file.bin"],
    );
    assert_eq!(got, "status=200 body=ok");
    let (connect, inner) = server.join().expect("server");
    assert_eq!(
        connect, "CONNECT updates.example.invalid:80 HTTP/1.1",
        "the request must reach the proxy"
    );
    assert_eq!(inner, "GET /file.bin HTTP/1.1");
}

/// Linux has no system proxy source: without the environment there is none. (macOS and Windows
/// read the machine's own settings, which this test cannot know.)
fn no_env_no_proxy() {
    if cfg!(any(target_os = "macos", windows)) {
        return;
    }
    assert_eq!(child(&[], &["--proxy-for", URL]), "none");
}

/// A loopback port nothing listens on.
fn closed_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    listener.local_addr().expect("addr").port()
}

/// A loopback HTTP server that answers every request with `response` until `stop` is set, and
/// returns how many requests it saw.
fn serve(response: String) -> (u16, Arc<AtomicBool>, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("addr").port();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut seen = 0;
        while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream.set_nonblocking(false).expect("blocking");
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .expect("timeout");
                    read_head(&mut stream);
                    seen += 1;
                    stream.write_all(response.as_bytes()).expect("write");
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
        seen
    });
    (port, stop, handle)
}

const OK: &str = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

/// `direct` reaches a loopback server although every proxy variable names a closed port; the
/// control without `direct` goes to that proxy and fails.
fn direct_ignores_env_proxies() {
    let dead = format!("http://127.0.0.1:{}", closed_port());
    let env: Vec<(&str, &str)> = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
        .iter()
        .map(|v| (*v, dead.as_str()))
        .collect();

    let (port, stop, server) = serve(OK.to_owned());
    let url = format!("http://127.0.0.1:{port}/feed-stable.json");
    let got = child(&env, &["--fetch-with", "1", "0", &url]);
    assert_eq!(got, "status=200 body=ok", "direct");

    let control = child(&env, &["--fetch-with", "0", "0", &url]);
    stop.store(true, Ordering::SeqCst);
    assert!(control.starts_with("error="), "control reached: {control}");
    assert_eq!(
        server.join().expect("server"),
        1,
        "only the direct fetch reaches the server"
    );
}

/// With `max_redirects` 0 a 302 comes back as the answer: the redirect target sees no request.
/// The control with redirects on shows the target is reachable.
fn no_redirects_returns_the_302() {
    let (target, stop_target, target_server) = serve(OK.to_owned());
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{target}/x\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );
    let (port, stop, server) = serve(redirect);
    let url = format!("http://127.0.0.1:{port}/feed-stable.json");
    let got = child(&[], &["--fetch-with", "1", "0", &url]);
    assert_eq!(got, "status=302 body=", "the 302 is the answer");
    let control = child(&[], &["--fetch-with", "1", "5", &url]);
    stop.store(true, Ordering::SeqCst);
    stop_target.store(true, Ordering::SeqCst);
    assert_eq!(control, "status=200 body=ok", "control follows");
    assert_eq!(server.join().expect("server"), 2);
    assert_eq!(
        target_server.join().expect("target"),
        1,
        "only the control reaches the redirect target"
    );
}

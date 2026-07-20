#![cfg(windows)]

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dig2browser_client::{
    ArtifactMediaType, ArtifactRef, ClientConfig, CollectionId, CrawlCursor,
    CrawlEvent, CrawlEventKind, CrawlJobId, CrawlPhase, CrawlSpec, StationClient,
    TraceCursor,
};
#[cfg(feature = "crawler-test-hooks")]
use dig2browser_client::{InterruptedReason, TraceEventKind};
use tokio::io::AsyncReadExt;

struct CrawlFixture {
    address: SocketAddr,
    paths: Arc<Mutex<Vec<String>>>,
    page_2_requests: Arc<AtomicUsize>,
    release_first_page_2: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    listener_thread: Option<JoinHandle<()>>,
}

impl CrawlFixture {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .expect("bind crawler E2E controlled origin");
        let address = listener
            .local_addr()
            .expect("read crawler E2E controlled origin address");
        listener
            .set_nonblocking(true)
            .expect("make crawler E2E listener nonblocking");

        let paths = Arc::new(Mutex::new(Vec::new()));
        let page_2_requests = Arc::new(AtomicUsize::new(0));
        let release_first_page_2 = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));

        let listener_paths = Arc::clone(&paths);
        let listener_page_2_requests = Arc::clone(&page_2_requests);
        let listener_release = Arc::clone(&release_first_page_2);
        let listener_stopping = Arc::clone(&stopping);
        let listener_thread = thread::spawn(move || {
            while !listener_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let connection_paths = Arc::clone(&listener_paths);
                        let connection_page_2_requests =
                            Arc::clone(&listener_page_2_requests);
                        let connection_release = Arc::clone(&listener_release);
                        let connection_stopping = Arc::clone(&listener_stopping);
                        thread::spawn(move || {
                            let _ = serve_connection(
                                stream,
                                &connection_paths,
                                &connection_page_2_requests,
                                &connection_release,
                                &connection_stopping,
                            );
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("crawler E2E controlled origin failed: {error}"),
                }
            }
        });

        Self {
            address,
            paths,
            page_2_requests,
            release_first_page_2,
            stopping,
            listener_thread: Some(listener_thread),
        }
    }

    fn origin(&self) -> String {
        format!("http://{}", self.address)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.origin())
    }

    fn page_2_request_count(&self) -> usize {
        self.page_2_requests.load(Ordering::Acquire)
    }

    fn path_count(&self, expected: &str) -> usize {
        self.paths
            .lock()
            .expect("crawler E2E request paths remain available")
            .iter()
            .filter(|path| path.as_str() == expected)
            .count()
    }

    fn paths(&self) -> Vec<String> {
        self.paths
            .lock()
            .expect("crawler E2E request paths remain available")
            .clone()
    }

    fn release_first_page_2(&self) {
        self.release_first_page_2.store(true, Ordering::Release);
    }
}

impl Drop for CrawlFixture {
    fn drop(&mut self) {
        self.release_first_page_2.store(true, Ordering::Release);
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(listener_thread) = self.listener_thread.take() {
            let _ = listener_thread.join();
        }
    }
}

fn serve_connection(
    mut stream: TcpStream,
    paths: &Mutex<Vec<String>>,
    page_2_requests: &AtomicUsize,
    release_first_page_2: &AtomicBool,
    stopping: &AtomicBool,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(4_096);
    loop {
        let mut chunk = [0_u8; 1_024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() >= 16 * 1_024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "crawler E2E request headers exceed limit",
            ));
        }
    }

    let request = String::from_utf8_lossy(&request);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
        .split('?')
        .next()
        .unwrap_or("/")
        .to_owned();
    paths
        .lock()
        .expect("crawler E2E request paths remain available")
        .push(path.clone());

    let (status, body) = match path.as_str() {
        "/seed" => (
            "200 OK",
            concat!(
                "<!doctype html><html><head><title>crawl seed</title></head><body>",
                "<main data-crawl-page=\"seed\">seed</main>",
                "<a href=\"/page-2\">page two</a>",
                "<a href=\"/page-2#duplicate\">duplicate page two</a>",
                "<a href=\"/seed\">cycle to seed</a>",
                "<a href=\"http://example.invalid/outside\">outside scope</a>",
                "</body></html>"
            ).to_owned(),
        ),
        "/page-2" => {
            let attempt = page_2_requests.fetch_add(1, Ordering::AcqRel) + 1;
            if attempt == 1 {
                while !release_first_page_2.load(Ordering::Acquire)
                    && !stopping.load(Ordering::Acquire)
                {
                    thread::sleep(Duration::from_millis(5));
                }
            }
            (
                "200 OK",
                concat!(
                    "<!doctype html><html><head><title>crawl page two</title></head><body>",
                    "<main data-crawl-page=\"page-2\">page two</main>",
                    "<a href=\"/seed#cycle\">cycle to seed</a>",
                    "</body></html>"
                ).to_owned(),
            )
        }
        "/post-commit" => {
            let mut body = String::with_capacity(1024 * 1024);
            body.push_str("<!doctype html><title>post commit</title><main data-crawl-page=\"post-commit\">");
            for index in 0..10_000 {
                body.push_str("<a href=\"/post-commit#");
                body.push_str(&index.to_string());
                body.push_str("\">same page</a>");
            }
            while body.len() < 1024 * 1024 {
                body.push_str("post-commit-padding-");
            }
            body.push_str("</main>");
            ("200 OK", body)
        }
        _ => (
            "404 Not Found",
            "<!doctype html><title>not found</title>".to_owned(),
        ),
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_resumes_multi_page_crawl_after_hard_kill_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-resume-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-resume-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    for path in [&profiles, &traces, &crawls] {
        std::fs::create_dir_all(path).expect("create crawler E2E durable root");
    }

    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid crawler E2E client config"),
    )
    .await
    .expect("connect crawler E2E client");

    let seed_url = fixture.url("/seed");
    let page_2_url = fixture.url("/page-2");
    let spec = CrawlSpec::new(
        vec![seed_url.clone()],
        vec![fixture.origin()],
        2,
        1,
        2,
    )
    .expect("valid bounded crawler E2E spec");
    let job_id = client
        .begin_crawl("crawler-resume-public", spec)
        .await
        .expect("begin crawler E2E job");

    let (cursor, mut events) = wait_for_seed_and_blocked_page_2(
        &client,
        job_id,
        &fixture,
        &seed_url,
        &page_2_url,
    )
    .await;
    let before_crash = client
        .crawl_status(job_id)
        .await
        .expect("read pre-crash crawl status");
    assert_eq!(before_crash.phase(), CrawlPhase::Running);
    assert_eq!(before_crash.succeeded(), 1);
    assert_eq!(before_crash.in_flight(), 1);

    daemon
        .kill()
        .await
        .expect("hard-kill crawler E2E station daemon");
    daemon
        .wait()
        .await
        .expect("reap hard-killed crawler E2E station daemon");
    let _ = read_child_output(&mut daemon).await;
    fixture.release_first_page_2();

    let mut successor = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    assert!(
        client.health().await.is_err(),
        "stale crawler transport unexpectedly survived station hard kill"
    );
    client
        .health()
        .await
        .expect("same crawler client reconnects to successor station");

    events = wait_for_complete_crawl(&client, job_id, cursor, events).await;
    let status = client
        .crawl_status(job_id)
        .await
        .expect("read completed crawl status");
    assert_eq!(status.phase(), CrawlPhase::Succeeded);
    assert_eq!(status.discovered(), 2);
    assert_eq!(status.queued(), 0);
    assert_eq!(status.in_flight(), 0);
    assert_eq!(status.succeeded(), 2);
    assert_eq!(status.failed(), 0);
    assert!(status.retried() >= 1);

    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() == CrawlEventKind::JobStarted)
            .count(),
        1,
        "crawl restart duplicated JobStarted"
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.kind() == CrawlEventKind::JobSucceeded)
            .count(),
        1,
        "crawl exposed an invalid terminal event history"
    );
    assert!(
        events.iter().any(|event| {
            event.kind() == CrawlEventKind::Recovered
                && event.canonical_url() == Some(page_2_url.as_str())
                && event.attempt() == 1
                && event.detail() == Some("lease recovery")
        }),
        "successor did not expose durable recovery of the interrupted page"
    );

    let succeeded = events
        .iter()
        .filter(|event| event.kind() == CrawlEventKind::PageSucceeded)
        .collect::<Vec<_>>();
    assert_eq!(succeeded.len(), 2, "crawl committed a duplicate durable page");
    let succeeded_urls = succeeded
        .iter()
        .map(|event| event.canonical_url().expect("successful page has URL"))
        .collect::<HashSet<_>>();
    assert_eq!(succeeded_urls.len(), 2);
    assert!(succeeded_urls.contains(seed_url.as_str()));
    assert!(succeeded_urls.contains(page_2_url.as_str()));
    let collection_ids = succeeded
        .iter()
        .map(|event| {
            event
                .page()
                .expect("successful page has durable artifact")
                .collection_id()
        })
        .collect::<HashSet<_>>();
    assert_eq!(collection_ids.len(), 2);

    let page_2_success = succeeded
        .iter()
        .find(|event| event.canonical_url() == Some(page_2_url.as_str()))
        .expect("page two completed after recovery");
    assert!(
        page_2_success.attempt() >= 2,
        "recovered page did not run a successor attempt"
    );
    assert!(fixture.page_2_request_count() >= 2);
    assert_eq!(fixture.path_count("/seed"), 1);
    assert!(fixture.path_count("/page-2") >= 2);
    assert!(
        fixture
            .paths()
            .iter()
            .all(|path| matches!(path.as_str(), "/seed" | "/page-2")),
        "crawler contacted a URL outside the controlled scope"
    );

    for event in succeeded {
        assert_eq!(event.http_status(), Some(200));
        let canonical_url = event
            .canonical_url()
            .expect("successful page has canonical URL");
        let page = event
            .page()
            .expect("successful page has durable HTML artifact");
        assert_eq!(page.html().media_type(), ArtifactMediaType::TextHtmlUtf8);
        let bytes = read_complete_artifact(
            &client,
            page.collection_id(),
            page.html(),
        )
        .await;
        assert_eq!(u64::try_from(bytes.len()).unwrap(), page.html().len());
        assert_eq!(
            dig2browser::digest::sha256_bytes(&bytes),
            *page.html().sha256()
        );
        let html = String::from_utf8(bytes).expect("crawler artifact is UTF-8 HTML");
        if canonical_url == seed_url {
            assert!(html.contains("data-crawl-page=\"seed\""));
            assert!(html.contains("href=\"/page-2\""));
        } else if canonical_url == page_2_url {
            assert!(html.contains("data-crawl-page=\"page-2\""));
        } else {
            panic!("unexpected successful crawl URL: {canonical_url}");
        }
    }

    assert!(
        client.cancel_crawl(job_id).await.is_err(),
        "completed crawl must reject cancellation"
    );

    client
        .shutdown()
        .await
        .expect("request clean crawler successor shutdown");
    assert_clean_exit(&mut successor).await;
    remove_tree(&root).await;
}

#[cfg(feature = "crawler-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_reconciles_receipt_before_terminal_hard_kill_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-preterminal-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-preterminal-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    let pause_root = root.join("receipt-pause");
    for path in [&profiles, &traces, &crawls, &pause_root] {
        std::fs::create_dir_all(path).expect("create preterminal E2E durable root");
    }

    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_receipt_pause(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
        &pause_root,
    );
    let client = StationClient::connect(
        ClientConfig::new(&pipe_name, Duration::from_secs(15), Duration::from_secs(90))
            .expect("valid preterminal E2E client config"),
    )
    .await
    .expect("connect preterminal E2E client");
    let seed_url = fixture.url("/seed");
    let job_id = client
        .begin_crawl(
            "crawler-preterminal-public",
            CrawlSpec::new(
                vec![seed_url.clone()],
                vec![fixture.origin()],
                1,
                0,
                0,
            )
            .expect("valid preterminal E2E spec"),
        )
        .await
        .expect("begin preterminal E2E crawl");
    wait_for_file(&pause_root.join("receipt-paused")).await;
    let collection_id = page_collection_id_for_test(job_id, &seed_url, 1);
    let collection_dir = traces
        .join("collections")
        .join(collection_id_hex(collection_id));
    assert!(collection_dir.join("00000001.event").is_file());
    assert!(collection_dir.join("00000002.event").is_file());
    assert!(
        !collection_dir.join("00000003.event").exists(),
        "test hook paused after terminal trace"
    );
    assert_eq!(fixture.path_count("/seed"), 1);

    daemon.kill().await.expect("hard-kill preterminal station");
    daemon.wait().await.expect("reap preterminal station");
    let _ = read_child_output(&mut daemon).await;

    let mut trace_only = spawn_stationd_trace_only(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &fixture.origin(),
    );
    client.health().await.expect_err("stale preterminal transport survives kill");
    client.health().await.expect("connect trace-only successor");
    assert!(!client
        .read_trace(collection_id, TraceCursor::START, 64)
        .await
        .expect("trace-only successor preserves receipt-backed collection")
        .is_complete());
    client.shutdown().await.expect("shutdown trace-only successor");
    assert_clean_exit(&mut trace_only).await;

    let mut successor = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    client.health().await.expect_err("stale trace-only transport survives shutdown");
    client.health().await.expect("reconnect preterminal successor");
    let events = wait_for_complete_crawl(
        &client,
        job_id,
        CrawlCursor::START,
        Vec::new(),
    )
    .await;
    assert_eq!(fixture.path_count("/seed"), 1, "successor repeated outbound");
    assert_eq!(
        events.iter().filter(|event| event.kind() == CrawlEventKind::PageStarted).count(),
        1,
        "preterminal reconciliation created a duplicate attempt"
    );
    let succeeded = events
        .iter()
        .find(|event| event.kind() == CrawlEventKind::PageSucceeded)
        .expect("receipt-backed page succeeded durably");
    assert_eq!(succeeded.attempt(), 1);
    assert_eq!(succeeded.canonical_url(), Some(seed_url.as_str()));
    assert_eq!(succeeded.http_status(), Some(200));
    assert!(
        events.iter().all(|event| event.kind() != CrawlEventKind::Recovered),
        "exact receipt reconciliation must precede lease recovery"
    );
    assert!(client
        .read_trace(collection_id, TraceCursor::START, 64)
        .await
        .expect("read reconciled terminal trace")
        .is_complete());
    client.shutdown().await.expect("shutdown preterminal successor");
    assert_clean_exit(&mut successor).await;
    remove_tree(&root).await;
}

#[cfg(feature = "crawler-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_clean_shutdown_reconciles_receipt_before_lease_recovery_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-clean-receipt-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-clean-receipt-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    let pause_root = root.join("receipt-pause");
    for path in [&profiles, &traces, &crawls, &pause_root] {
        std::fs::create_dir_all(path).expect("create clean-shutdown E2E durable root");
    }

    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_receipt_pause(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
        &pause_root,
    );
    let config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid clean-shutdown E2E client config");
    let client = StationClient::connect(config.clone())
        .await
        .expect("connect clean-shutdown E2E client");
    let shutdown_client = StationClient::connect(config)
        .await
        .expect("connect clean-shutdown controller");
    let seed_url = fixture.url("/seed");
    let job_id = client
        .begin_crawl(
            "crawler-clean-receipt-public",
            CrawlSpec::new(
                vec![seed_url.clone()],
                vec![fixture.origin()],
                1,
                0,
                0,
            )
            .expect("valid clean-shutdown E2E spec"),
        )
        .await
        .expect("begin clean-shutdown E2E crawl");
    wait_for_file(&pause_root.join("receipt-paused")).await;
    assert_eq!(fixture.path_count("/seed"), 1);

    let shutdown = tokio::spawn(async move { shutdown_client.shutdown().await });
    wait_for_file(&pause_root.join("shutdown-stop-set")).await;
    std::fs::write(pause_root.join("receipt-release"), b"release\n")
        .expect("release receipt-paused collection");
    shutdown
        .await
        .expect("join clean shutdown request")
        .expect("request clean receipt shutdown");
    assert_clean_exit(&mut daemon).await;

    let mut successor = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    client.health().await.expect_err("stale clean-shutdown transport survives exit");
    client.health().await.expect("connect clean-shutdown successor");
    let events = wait_for_complete_crawl(
        &client,
        job_id,
        CrawlCursor::START,
        Vec::new(),
    )
    .await;
    assert_eq!(fixture.path_count("/seed"), 1, "successor repeated outbound");
    assert_eq!(
        events.iter().filter(|event| event.kind() == CrawlEventKind::PageSucceeded).count(),
        1
    );
    assert!(events.iter().all(|event| event.kind() != CrawlEventKind::Recovered));
    client.shutdown().await.expect("shutdown clean-shutdown successor");
    assert_clean_exit(&mut successor).await;
    remove_tree(&root).await;
}

#[cfg(feature = "crawler-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_exposes_job_unavailable_when_fatal_state_cannot_persist_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-fatal-persist-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-fatal-persist-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    for path in [&profiles, &traces, &crawls] {
        std::fs::create_dir_all(path).expect("create fatal-persistence E2E durable root");
    }

    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_fatal_persistence_failure(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    let client = StationClient::connect(
        ClientConfig::new(&pipe_name, Duration::from_secs(15), Duration::from_secs(90))
            .expect("valid fatal-persistence E2E client config"),
    )
    .await
    .expect("connect fatal-persistence E2E client");
    let seed_url = fixture.url("/seed");
    let spec = CrawlSpec::new(
        vec![seed_url],
        vec![fixture.origin()],
        1,
        0,
        0,
    )
    .expect("valid fatal-persistence E2E spec");
    let job_id = client
        .begin_crawl("crawler-fatal-persist-public", spec.clone())
        .await
        .expect("begin fatal-persistence E2E crawl");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let unavailable = loop {
        match client.crawl_status(job_id).await {
            Ok(status) => assert_eq!(status.phase(), CrawlPhase::Running),
            Err(error) => break error,
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "fatal persistence failure remained falsely Running"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    assert!(format!("{unavailable}").contains("crawler unavailable"));
    assert!(
        client
            .begin_crawl_with_id("crawler-fatal-persist-public", job_id, spec)
            .await
            .is_err(),
        "unavailable job was incorrectly accepted as idempotent"
    );
    assert_eq!(fixture.path_count("/seed"), 0, "injected fatal runner reached outbound");
    client.shutdown().await.expect("shutdown fatal-persistence station");
    assert_clean_exit(&mut daemon).await;
    remove_tree(&root).await;
}

#[cfg(feature = "crawler-test-hooks")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_preserves_cancelled_job_over_receipt_before_terminal_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-cancel-receipt-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-cancel-receipt-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    let pause_root = root.join("receipt-pause");
    for path in [&profiles, &traces, &crawls, &pause_root] {
        std::fs::create_dir_all(path).expect("create cancelled-receipt E2E root");
    }

    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_receipt_pause(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
        &pause_root,
    );
    let client = StationClient::connect(
        ClientConfig::new(&pipe_name, Duration::from_secs(15), Duration::from_secs(90))
            .expect("valid cancelled-receipt client config"),
    )
    .await
    .expect("connect cancelled-receipt client");
    let seed_url = fixture.url("/seed");
    let job_id = client
        .begin_crawl(
            "crawler-cancel-receipt-public",
            CrawlSpec::new(
                vec![seed_url.clone()],
                vec![fixture.origin()],
                1,
                0,
                0,
            )
            .expect("valid cancelled-receipt spec"),
        )
        .await
        .expect("begin cancelled-receipt crawl");
    wait_for_file(&pause_root.join("receipt-paused")).await;
    let collection_id = page_collection_id_for_test(job_id, &seed_url, 1);
    client
        .cancel_crawl(job_id)
        .await
        .expect("cancel crawl after receipt became durable");
    assert_eq!(
        client
            .crawl_status(job_id)
            .await
            .expect("read cancelled-receipt status")
            .phase(),
        CrawlPhase::Cancelled
    );
    daemon.kill().await.expect("hard-kill cancelled-receipt station");
    daemon.wait().await.expect("reap cancelled-receipt station");
    let _ = read_child_output(&mut daemon).await;

    let mut successor = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    client.health().await.expect_err("stale cancelled transport survives kill");
    client.health().await.expect("connect cancelled-receipt successor");
    assert_eq!(
        client
            .crawl_status(job_id)
            .await
            .expect("read successor cancelled status")
            .phase(),
        CrawlPhase::Cancelled
    );
    let events = wait_for_complete_crawl(
        &client,
        job_id,
        CrawlCursor::START,
        Vec::new(),
    )
    .await;
    assert!(events.iter().any(|event| event.kind() == CrawlEventKind::JobCancelled));
    assert!(events.iter().all(|event| {
        !matches!(
            event.kind(),
            CrawlEventKind::PageSucceeded | CrawlEventKind::Recovered
        )
    }));
    assert_eq!(fixture.path_count("/seed"), 1, "cancelled job resumed outbound");
    let trace = client
        .read_trace(collection_id, TraceCursor::START, 64)
        .await
        .expect("read cancelled receipt trace");
    assert!(trace.is_complete());
    assert!(matches!(
        trace.events().last().map(|event| event.kind()),
        Some(TraceEventKind::Interrupted(
            InterruptedReason::SuccessorReconciliation
        ))
    ));
    client.shutdown().await.expect("shutdown cancelled-receipt successor");
    assert_clean_exit(&mut successor).await;
    remove_tree(&root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_reconciles_post_terminal_hard_kill_without_duplicate_outbound_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-post-commit-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-post-commit-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    for path in [&profiles, &traces, &crawls] {
        std::fs::create_dir_all(path).expect("create post-commit E2E durable root");
    }

    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    let client = StationClient::connect(
        ClientConfig::new(&pipe_name, Duration::from_secs(15), Duration::from_secs(90))
            .expect("valid post-commit E2E client config"),
    )
    .await
    .expect("connect post-commit E2E client");
    let seed_url = fixture.url("/post-commit");
    let job_id = client
        .begin_crawl(
            "crawler-post-commit-public",
            CrawlSpec::new(
                vec![seed_url.clone()],
                vec![fixture.origin()],
                2,
                1,
                0,
            )
            .expect("valid post-commit E2E spec"),
        )
        .await
        .expect("begin post-commit E2E crawl");
    let collection_id = page_collection_id_for_test(job_id, &seed_url, 1);
    wait_for_terminal_trace(&client, collection_id).await;
    let requests_before_kill = fixture.path_count("/post-commit");
    assert!(requests_before_kill >= 1);
    assert_eq!(
        client.crawl_status(job_id).await.expect("read post-commit status").phase(),
        CrawlPhase::Running,
        "crawler crossed the controlled post-commit kill point before the hard kill"
    );

    daemon.kill().await.expect("hard-kill post-commit station");
    daemon.wait().await.expect("reap post-commit station");
    let _ = read_child_output(&mut daemon).await;

    let mut successor = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    client.health().await.expect_err("stale post-commit transport survives kill");
    client.health().await.expect("reconnect post-commit successor");
    let events = wait_for_complete_crawl(
        &client,
        job_id,
        CrawlCursor::START,
        Vec::new(),
    )
    .await;
    assert_eq!(
        fixture.path_count("/post-commit"),
        requests_before_kill,
        "successor repeated outbound after post-commit reconciliation"
    );
    assert_eq!(
        events.iter().filter(|event| event.kind() == CrawlEventKind::PageStarted).count(),
        1,
        "post-commit reconciliation created a duplicate attempt"
    );
    let succeeded = events
        .iter()
        .find(|event| event.kind() == CrawlEventKind::PageSucceeded)
        .expect("post-commit page succeeded durably");
    assert_eq!(succeeded.attempt(), 1);
    assert_eq!(succeeded.canonical_url(), Some(seed_url.as_str()));
    assert_eq!(succeeded.http_status(), Some(200));
    assert!(
        events.iter().all(|event| event.kind() != CrawlEventKind::Recovered),
        "receipt reconciliation must complete the exact in-flight lease"
    );
    client.shutdown().await.expect("shutdown post-commit successor");
    assert_clean_exit(&mut successor).await;
    remove_tree(&root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_crawl_authority_is_fail_closed_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-authority-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-authority-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    for path in [&profiles, &traces, &crawls] {
        std::fs::create_dir_all(path).expect("create authority E2E durable root");
    }
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
    );
    let client = StationClient::connect(
        ClientConfig::new(&pipe_name, Duration::from_secs(15), Duration::from_secs(90))
            .expect("valid authority E2E client config"),
    )
    .await
    .expect("connect authority E2E client");
    let blocked_url = fixture.url("/page-2");
    client
        .begin_crawl(
            "crawler-authority-public",
            CrawlSpec::new(
                vec![blocked_url.clone()],
                vec![fixture.origin()],
                1,
                0,
                0,
            )
            .expect("valid authority E2E spec"),
        )
        .await
        .expect("begin authority E2E crawl");
    wait_for_path_count(&fixture, "/page-2", 1).await;
    daemon.kill().await.expect("hard-kill authority station");
    daemon.wait().await.expect("reap authority station");
    let _ = read_child_output(&mut daemon).await;
    fixture.release_first_page_2();

    let mut read_only = spawn_stationd_with_permissions(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
        &["--allow-durable-read", "--allow-durable-write"],
    );
    client.health().await.expect_err("stale authority transport survives kill");
    client.health().await.expect("connect station without crawl permissions");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(fixture.path_count("/page-2"), 1, "station resumed crawl without crawl authority");
    client.shutdown().await.expect("shutdown station without crawl permissions");
    assert_clean_exit(&mut read_only).await;

    let mut no_durable_write = spawn_stationd_with_permissions(
        stationd,
        &pipe_name,
        &profiles,
        &traces,
        &crawls,
        &fixture.origin(),
        &["--allow-durable-read", "--allow-crawl-read", "--allow-crawl-write"],
    );
    assert!(
        client.health().await.is_err(),
        "stale read-only transport unexpectedly survived shutdown"
    );
    client.health().await.expect("connect station without durable write");
    let denied = client
        .begin_crawl(
            "crawler-authority-denied",
            CrawlSpec::new(
                vec![fixture.url("/seed")],
                vec![fixture.origin()],
                1,
                0,
                0,
            )
            .expect("valid denied authority E2E spec"),
        )
        .await;
    assert!(denied.is_err(), "Begin crawl succeeded without durable_write");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fixture.path_count("/page-2"), 1);
    assert_eq!(fixture.path_count("/seed"), 0);
    client.shutdown().await.expect("shutdown station without durable write");
    assert_clean_exit(&mut no_durable_write).await;
    remove_tree(&root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn crawl_cancel_is_idempotent_only_for_cancelled_job_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = CrawlFixture::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-crawler-cancel-e2e-{unique}");
    let root = e2e_temp_base().join(format!("dig2browser-crawler-cancel-e2e-{unique}"));
    let profiles = root.join("profiles");
    let traces = root.join("traces");
    let crawls = root.join("crawls");
    for path in [&profiles, &traces, &crawls] {
        std::fs::create_dir_all(path).expect("create cancel E2E durable root");
    }
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles, &traces, &crawls, &fixture.origin());
    let client = StationClient::connect(
        ClientConfig::new(&pipe_name, Duration::from_secs(15), Duration::from_secs(90))
            .expect("valid cancel E2E client config"),
    )
    .await
    .expect("connect cancel E2E client");
    let job_id = client
        .begin_crawl(
            "crawler-cancel-public",
            CrawlSpec::new(
                vec![fixture.url("/page-2")],
                vec![fixture.origin()],
                1,
                0,
                0,
            )
            .expect("valid cancel E2E spec"),
        )
        .await
        .expect("begin cancel E2E crawl");
    wait_for_path_count(&fixture, "/page-2", 1).await;
    client.cancel_crawl(job_id).await.expect("cancel running crawl");
    client.cancel_crawl(job_id).await.expect("cancel cancelled crawl idempotently");
    assert_eq!(client.crawl_status(job_id).await.expect("read cancelled status").phase(), CrawlPhase::Cancelled);
    fixture.release_first_page_2();
    client.shutdown().await.expect("shutdown cancel E2E station");
    assert_clean_exit(&mut daemon).await;
    remove_tree(&root).await;
}

async fn wait_for_seed_and_blocked_page_2(
    client: &StationClient,
    job_id: CrawlJobId,
    fixture: &CrawlFixture,
    seed_url: &str,
    page_2_url: &str,
) -> (CrawlCursor, Vec<CrawlEvent>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut cursor = CrawlCursor::START;
    let mut events = Vec::new();
    loop {
        let page = client
            .read_crawl_events(job_id, cursor, 64)
            .await
            .expect("poll pre-crash crawl events");
        events.extend_from_slice(page.events());
        cursor = page.next_cursor();
        let seed_succeeded = events.iter().any(|event| {
            event.kind() == CrawlEventKind::PageSucceeded
                && event.canonical_url() == Some(seed_url)
        });
        let page_2_started = events.iter().any(|event| {
            event.kind() == CrawlEventKind::PageStarted
                && event.canonical_url() == Some(page_2_url)
                && event.attempt() == 1
        });
        if seed_succeeded && page_2_started && fixture.page_2_request_count() >= 1 {
            return (cursor, events);
        }
        assert!(!page.is_complete(), "crawl completed before the hard-kill point");
        assert!(
            tokio::time::Instant::now() < deadline,
            "crawler did not reach the controlled hard-kill point: {events:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_terminal_trace(client: &StationClient, collection_id: CollectionId) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(page) = client
            .read_trace(collection_id, TraceCursor::START, 64)
            .await
        {
            if page.is_complete() {
                return;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "collection trace did not reach the post-commit point"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

async fn wait_for_path_count(fixture: &CrawlFixture, path: &str, count: usize) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while fixture.path_count(path) < count {
        assert!(
            tokio::time::Instant::now() < deadline,
            "controlled origin did not receive {path}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg(feature = "crawler-test-hooks")]
async fn wait_for_file(path: &Path) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "test hook did not reach receipt pause: {}",
            path.display()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn page_collection_id_for_test(
    job_id: CrawlJobId,
    url: &str,
    attempt: u32,
) -> CollectionId {
    let mut bytes = Vec::with_capacity(64 + url.len());
    bytes.extend_from_slice(b"dig2browser-crawl-collection-v1");
    bytes.extend_from_slice(job_id.as_bytes());
    bytes.extend_from_slice(url.as_bytes());
    bytes.extend_from_slice(&attempt.to_le_bytes());
    let digest = dig2browser::digest::sha256_bytes(&bytes);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] {
        id[15] = 1;
    }
    CollectionId::new(id).expect("deterministic crawler collection id is valid")
}

#[cfg(feature = "crawler-test-hooks")]
fn collection_id_hex(collection_id: CollectionId) -> String {
    let mut value = String::with_capacity(32);
    for byte in collection_id.as_bytes() {
        use std::fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

async fn wait_for_complete_crawl(
    client: &StationClient,
    job_id: CrawlJobId,
    mut cursor: CrawlCursor,
    mut events: Vec<CrawlEvent>,
) -> Vec<CrawlEvent> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    loop {
        let page = client
            .read_crawl_events(job_id, cursor, 64)
            .await
            .expect("poll successor crawl events");
        events.extend_from_slice(page.events());
        cursor = page.next_cursor();
        if page.is_complete() {
            return events;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "successor crawl did not reach terminal state: {events:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn read_complete_artifact(
    client: &StationClient,
    collection_id: dig2browser_client::CollectionId,
    artifact: &ArtifactRef,
) -> Vec<u8> {
    let mut offset = 0_u64;
    let mut bytes = Vec::new();
    loop {
        let chunk = client
            .read_artifact_chunk(collection_id, *artifact.sha256(), offset, 1_024)
            .await
            .expect("read crawler durable HTML artifact");
        assert_eq!(chunk.total_len(), artifact.len());
        bytes.extend_from_slice(chunk.bytes());
        offset = offset
            .checked_add(u64::try_from(chunk.bytes().len()).unwrap())
            .expect("crawler artifact offset remains bounded");
        if chunk.is_eof() {
            return bytes;
        }
    }
}

fn spawn_stationd(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    crawls: &Path,
    allowed_origin: &str,
) -> tokio::process::Child {
    spawn_stationd_with_permissions(
        stationd,
        pipe_name,
        profiles,
        traces,
        crawls,
        allowed_origin,
        &[
            "--allow-durable-read",
            "--allow-durable-write",
            "--allow-crawl-read",
            "--allow-crawl-write",
        ],
    )
}

fn spawn_stationd_with_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    crawls: &Path,
    allowed_origin: &str,
    permissions: &[&str],
) -> tokio::process::Child {
    spawn_stationd_configured(
        stationd,
        pipe_name,
        StationdRoots { profiles, traces, crawls: Some(crawls) },
        allowed_origin,
        permissions,
        None,
        false,
    )
}

#[cfg(feature = "crawler-test-hooks")]
fn spawn_stationd_with_receipt_pause(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    crawls: &Path,
    allowed_origin: &str,
    pause_root: &Path,
) -> tokio::process::Child {
    spawn_stationd_configured(
        stationd,
        pipe_name,
        StationdRoots { profiles, traces, crawls: Some(crawls) },
        allowed_origin,
        &[
            "--allow-durable-read",
            "--allow-durable-write",
            "--allow-crawl-read",
            "--allow-crawl-write",
        ],
        Some(pause_root),
        false,
    )
}

#[cfg(feature = "crawler-test-hooks")]
fn spawn_stationd_with_fatal_persistence_failure(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    crawls: &Path,
    allowed_origin: &str,
) -> tokio::process::Child {
    spawn_stationd_configured(
        stationd,
        pipe_name,
        StationdRoots { profiles, traces, crawls: Some(crawls) },
        allowed_origin,
        &[
            "--allow-durable-read",
            "--allow-durable-write",
            "--allow-crawl-read",
            "--allow-crawl-write",
        ],
        None,
        true,
    )
}

#[cfg(feature = "crawler-test-hooks")]
fn spawn_stationd_trace_only(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    traces: &Path,
    allowed_origin: &str,
) -> tokio::process::Child {
    spawn_stationd_configured(
        stationd,
        pipe_name,
        StationdRoots { profiles, traces, crawls: None },
        allowed_origin,
        &["--allow-durable-read", "--allow-durable-write"],
        None,
        false,
    )
}

#[derive(Clone, Copy)]
struct StationdRoots<'a> {
    profiles: &'a Path,
    traces: &'a Path,
    crawls: Option<&'a Path>,
}

fn spawn_stationd_configured(
    stationd: &str,
    pipe_name: &str,
    roots: StationdRoots<'_>,
    allowed_origin: &str,
    permissions: &[&str],
    receipt_pause_root: Option<&Path>,
    fail_crawl_job_persistence: bool,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    command.args([
        "--pipe-name",
        pipe_name,
        "--profiles-root",
        roots.profiles.to_str().expect("profiles path is UTF-8"),
        "--trace-root",
        roots.traces.to_str().expect("trace path is UTF-8"),
    ]);
    if let Some(crawls) = roots.crawls {
        command.args([
            "--crawl-root",
            crawls.to_str().expect("crawl path is UTF-8"),
        ]);
    }
    command.args([
        "--runtime",
        "lightweight",
        "--max-resident",
        "1",
        "--max-in-flight",
        "2",
        "--max-connections",
        "4",
        "--timeout-seconds",
        "90",
        "--drain-seconds",
        "15",
        "--allow-origin",
        allowed_origin,
        "--allow-private-peer",
        "127.0.0.1",
        "--allow-remote-shutdown",
        "--allow-interactive-tasks",
    ]);
    command.args(permissions);
    if let Some(root) = receipt_pause_root {
        command
            .env("DIG2BROWSER_TEST_PAUSE_AFTER_CRAWL_RECEIPT", root)
            .env("DIG2BROWSER_TEST_CRAWL_LEASE_MS", "1");
    }
    if fail_crawl_job_persistence {
        command.env("DIG2BROWSER_TEST_FAIL_CRAWL_JOB_PERSISTENCE", "1");
    }
    command
        .env("HTTP_PROXY", "http://127.0.0.1:1")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("ALL_PROXY", "http://127.0.0.1:1")
        .env("NO_PROXY", "*")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn crawler E2E station daemon")
}

async fn assert_clean_exit(daemon: &mut tokio::process::Child) {
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("crawler successor exit timeout")
        .expect("wait for crawler successor");
    assert!(status.success(), "crawler successor failed: {status}");
    let (stdout, stderr) = read_child_output(daemon).await;
    assert!(stderr.is_empty(), "crawler successor wrote stderr: {stderr}");
    assert!(stdout.contains("\"event\":\"station_exit\""));
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
    assert!(stdout.contains("\"drain_timed_out\":false"));
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream
            .read_to_string(&mut stdout)
            .await
            .expect("read crawler station stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_string(&mut stderr)
            .await
            .expect("read crawler station stderr");
    }
    (stdout, stderr)
}

async fn e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL
        .acquire()
        .await
        .expect("crawler daemon E2E semaphore remains open")
}

fn e2e_temp_base() -> PathBuf {
    std::env::var_os("DIG2BROWSER_E2E_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\tmp"))
}

async fn remove_tree(path: &Path) {
    for _ in 0..30 {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove crawler E2E roots: {}", path.display());
}

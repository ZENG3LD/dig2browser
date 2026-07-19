#![cfg(windows)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dig2browser::identity::ProfileOwnershipGuard;
use dig2browser_client::{
    BrowserPersona, ClientConfig, ClientError, CollectionTask, FailureClass,
    IdentitySessionStatus, MobilePersonaConfig, ProfileClass, ResponseStatus,
    SessionHealthProbe, SessionPhase, SessionStateUpdate, StationClient, StationStatus,
    TaskCapturePolicy, TaskReply, TaskStep,
};
use tokio::io::AsyncReadExt;

struct FixtureServer {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl FixtureServer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind daemon fixture");
        let address = listener.local_addr().expect("daemon fixture address");
        listener
            .set_nonblocking(true)
            .expect("make daemon fixture nonblocking");
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_stopping = Arc::clone(&stopping);
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread::spawn(move || {
                            let _ = serve_connection(stream);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("daemon fixture listener failed: {error}"),
                }
            }
        });
        Self {
            address,
            stopping,
            thread: Some(thread),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://localhost:{}{}", self.address.port(), path)
    }
}

impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_millis(100));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_connection(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::with_capacity(4096);
    loop {
        let mut chunk = [0_u8; 1024];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..count]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if request.len() >= 16 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fixture request headers exceed limit",
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
        .unwrap_or("/");
    let requested_marker = path.trim_start_matches('/');
    let marker = if requested_marker == "auth-check" {
        if request.lines().any(|line| {
            line.to_ascii_lowercase().starts_with("cookie:")
                && line.contains("dig2browser_auth_e2e=cookie-secret")
        }) {
            "auth-check-ok"
        } else {
            "auth-check-missing"
        }
    } else {
        requested_marker
    };
    if marker == "force-close" {
        return Ok(());
    }
    let script = if requested_marker == "auth-bootstrap" {
        "<script>localStorage.setItem('dig2browser_auth_e2e','present');document.cookie='dig2browser_auth_e2e=cookie-secret; Path=/; Max-Age=3600'</script>"
    } else {
        ""
    };
    let body = format!(
        "<!doctype html><title>{marker}</title><main data-daemon-e2e=\"{marker}\">{marker}</main>{}{script}",
        match requested_marker {
            "session-ready" => "<section data-session-ready></section>",
            "session-reauth" => "<form data-session-reauth></form>",
            _ => "",
        }
    );
    let cookie = if requested_marker == "auth-bootstrap" {
        "Set-Cookie: dig2browser_auth_e2e=cookie-secret; Path=/; Max-Age=3600\r\n"
    } else {
        ""
    };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{cookie}Content-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_serves_concurrent_clients_and_drains_real_chromium_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-stationd-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create stationd E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);

    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid station client config");
    let first = StationClient::connect(client_config.clone())
        .await
        .expect("connect first station client");
    let second = StationClient::connect(client_config.clone())
        .await
        .expect("connect second station client");
    let observer = StationClient::connect(client_config)
        .await
        .expect("connect observer station client");

    let baseline = observer.status().await.expect("read baseline status");
    assert_eq!(baseline.resident_identities, 0);
    assert_eq!(baseline.captures_started, 0);
    assert_eq!(baseline.captures_in_flight, 0);
    assert!(baseline.accepted_connections >= 3);
    assert!(baseline.active_connections >= 3);
    assert_eq!(baseline.command_limit, 4);
    assert!(baseline.command_available <= baseline.command_limit);

    let endpoint_conflict_profiles =
        e2e_temp_base().join(format!("dig2browser-stationd-conflict-e2e-{unique}"));
    let mut endpoint_conflict = spawn_stationd(
        stationd,
        &pipe_name,
        &endpoint_conflict_profiles,
    );
    let endpoint_status = tokio::time::timeout(Duration::from_secs(15), endpoint_conflict.wait())
        .await
        .expect("endpoint conflict exit timeout")
        .expect("wait for endpoint conflict");
    assert!(!endpoint_status.success());
    let (_, endpoint_stderr) = read_child_output(&mut endpoint_conflict).await;
    assert!(endpoint_stderr.contains("\"error_class\":\"station_endpoint_unavailable\""));
    remove_tree(&endpoint_conflict_profiles).await;

    let root_conflict_pipe = format!("dig2browser-stationd-root-conflict-e2e-{unique}");
    let mut root_conflict = spawn_stationd(stationd, &root_conflict_pipe, &profiles);
    let root_status = tokio::time::timeout(Duration::from_secs(15), root_conflict.wait())
        .await
        .expect("profiles root conflict exit timeout")
        .expect("wait for profiles root conflict");
    assert!(!root_status.success());
    let (_, root_stderr) = read_child_output(&mut root_conflict).await;
    assert!(root_stderr.contains("\"error_class\":\"profiles_root_owned\""));
    observer
        .health()
        .await
        .expect("primary station survives ownership conflicts");

    let first_url = fixture.url("/first-client");
    let second_url = fixture.url("/second-client");
    let first_task = tokio::spawn(async move {
        first
            .capture("shared-public-profile", &first_url)
            .await
    });
    let second_task = tokio::spawn(async move {
        second
            .capture("shared-public-profile", &second_url)
            .await
    });
    let during = wait_for_status(&observer, |status| status.captures_in_flight >= 2).await;
    assert_eq!(during.captures_started, 2);
    assert!(during.resident_identities >= 1);
    assert!(during.active_leases >= 1);
    assert!(during.command_available <= during.command_limit);

    let first_capture = first_task
        .await
        .expect("join first capture")
        .expect("capture through first client");
    let second_capture = second_task
        .await
        .expect("join second capture")
        .expect("capture through second client");
    assert_eq!(first_capture.title.as_deref(), Some("first-client"));
    assert!(
        String::from_utf8_lossy(&first_capture.html)
            .contains("data-daemon-e2e=\"first-client\"")
    );
    assert_eq!(second_capture.title.as_deref(), Some("second-client"));
    assert!(
        String::from_utf8_lossy(&second_capture.html)
            .contains("data-daemon-e2e=\"second-client\"")
    );
    assert_eq!(&first_capture.png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(&second_capture.png[..8], b"\x89PNG\r\n\x1a\n");

    let after_success = observer.status().await.expect("read successful status");
    assert_eq!(after_success.resident_identities, 1);
    assert_eq!(after_success.ready_workers, 1);
    assert_eq!(after_success.active_leases, 0);
    assert_eq!(after_success.captures_started, 2);
    assert_eq!(after_success.captures_in_flight, 0);
    assert_eq!(after_success.captures_succeeded, 2);
    assert_eq!(after_success.captures_failed, 0);
    assert_eq!(after_success.last_failure_class, FailureClass::None);

    let task_url = fixture.url("/typed-task");
    let task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: task_url.clone(),
        },
        TaskStep::Wait {
            duration: Duration::from_millis(50),
        },
        TaskStep::Evaluate {
            script: "({marker: 'task-script'})".to_owned(),
        },
        TaskStep::ReadSelectorText {
            selector: "main".to_owned(),
        },
        TaskStep::Wheel {
            x: 1.0,
            y: 1.0,
            delta_x: 0.0,
            delta_y: 10.0,
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid typed daemon task");
    let task_result = observer
        .run_task("typed-task-profile", task)
        .await
        .expect("run typed task through client and station daemon");
    assert_eq!(task_result.replies().len(), 6);
    assert_eq!(
        task_result.replies()[2],
        TaskReply::ScriptJson("{\"marker\":\"task-script\"}".to_owned())
    );
    assert_eq!(
        task_result.replies()[3],
        TaskReply::Text("typed-task".to_owned())
    );
    let TaskReply::Capture(task_capture) = &task_result.replies()[5] else {
        panic!("typed task did not return evidence capture");
    };
    assert_eq!(task_capture.requested_url, task_url);
    assert_eq!(task_capture.final_url, task_url);
    assert_eq!(task_capture.http_status, Some(200));
    assert_eq!(task_capture.title, "typed-task");
    assert_eq!(task_capture.ready_state, "complete");
    assert!(String::from_utf8_lossy(&task_capture.html)
        .contains("data-daemon-e2e=\"typed-task\""));
    assert_eq!(&task_capture.png[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(
        task_capture.html_sha256,
        dig2browser::digest::sha256_bytes(&task_capture.html)
    );
    assert_eq!(
        task_capture.png_sha256,
        Some(dig2browser::digest::sha256_bytes(&task_capture.png))
    );
    assert_eq!(task_capture.protocol_version, dig2browser_protocol::PROTOCOL_VERSION);
    assert!(task_capture.collector_version.starts_with("dig2browser-station/"));

    assert!(
        observer
            .capture("failure-profile", fixture.url("/force-close"))
            .await
            .is_err(),
        "forced connection close unexpectedly produced a capture"
    );
    let after_failure = observer.status().await.expect("read failed status");
    assert_eq!(after_failure.captures_started, 4);
    assert_eq!(after_failure.captures_in_flight, 0);
    assert_eq!(after_failure.captures_succeeded, 3);
    assert_eq!(after_failure.captures_failed, 1);
    assert_eq!(after_failure.last_failure_class, FailureClass::CaptureFailed);
    assert!(after_failure.last_failure_unix_ms > 0);

    observer.shutdown().await.expect("request station drain");
    let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("station daemon exit timeout")
        .expect("wait for station daemon");
    assert!(status.success(), "station daemon failed: {status}");
    let (stdout, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "clean station wrote stderr: {stderr}");
    assert!(stdout.contains("\"event\":\"station_exit\""));
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
    assert!(stdout.contains("\"drain_timed_out\":false"));
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_explicit_chrome_and_edge_runtime_selection_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");

    for (runtime, expects_edge_brand) in [("chrome", false), ("edge", true)] {
        let unique = uuid::Uuid::new_v4();
        let pipe_name = format!("dig2browser-stationd-{runtime}-e2e-{unique}");
        let profiles = e2e_temp_base().join(format!(
            "dig2browser-stationd-{runtime}-e2e-{unique}"
        ));
        std::fs::create_dir_all(&profiles).expect("create explicit-runtime profiles root");
        let mut daemon = spawn_stationd_for_runtime(
            stationd,
            &pipe_name,
            &profiles,
            runtime,
        );
        let daemon_pid = daemon.id().expect("explicit-runtime stationd PID");

        let client = StationClient::connect(
            ClientConfig::new(
                &pipe_name,
                Duration::from_secs(15),
                Duration::from_secs(90),
            )
            .expect("valid explicit-runtime client config"),
        )
        .await
        .expect("connect explicit-runtime station client");
        let marker = format!("explicit-{runtime}-runtime");
        let url = fixture.url(&format!("/{marker}"));
        let task = CollectionTask::new(vec![
            TaskStep::Navigate { url: url.clone() },
            TaskStep::Evaluate {
                script: "navigator.userAgent".to_owned(),
            },
            TaskStep::Capture {
                policy: TaskCapturePolicy::EvidenceViewport,
            },
        ])
        .expect("valid explicit-runtime typed task");
        let result = client
            .run_task(&format!("explicit-{runtime}-profile"), task)
            .await
            .expect("run task through explicit browser runtime");

        assert_eq!(result.replies().len(), 3);
        let TaskReply::ScriptJson(user_agent_json) = &result.replies()[1] else {
            panic!("explicit {runtime} task did not return user agent JSON");
        };
        let user_agent = user_agent_json
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .expect("user agent is a JSON string");
        assert!(
            user_agent.contains("Chrome/"),
            "{runtime} user agent lacks Chromium brand: {user_agent}"
        );
        assert_eq!(
            user_agent.contains("Edg/"),
            expects_edge_brand,
            "{runtime} user agent did not match selected runtime: {user_agent}"
        );

        let TaskReply::Capture(capture) = &result.replies()[2] else {
            panic!("explicit {runtime} task did not return evidence capture");
        };
        assert_eq!(capture.requested_url, url);
        assert_eq!(capture.final_url, url);
        assert_eq!(capture.http_status, Some(200));
        assert_eq!(capture.title, marker);
        assert_eq!(capture.ready_state, "complete");
        assert!(
            String::from_utf8_lossy(&capture.html)
                .contains(&format!("data-daemon-e2e=\"{marker}\""))
        );
        assert_eq!(&capture.png[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(
            capture.html_sha256,
            dig2browser::digest::sha256_bytes(&capture.html)
        );
        assert_eq!(
            capture.png_sha256,
            Some(dig2browser::digest::sha256_bytes(&capture.png))
        );

        client
            .shutdown()
            .await
            .expect("request explicit-runtime station drain");
        let status = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
            .await
            .expect("explicit-runtime station daemon exit timeout")
            .expect("wait for explicit-runtime station daemon");
        assert!(
            status.success(),
            "{runtime} station daemon {daemon_pid} failed: {status}"
        );
        assert_eq!(
            daemon.try_wait().expect("recheck station daemon exit"),
            Some(status),
            "{runtime} station daemon {daemon_pid} remained alive"
        );
        let (stdout, stderr) = read_child_output(&mut daemon).await;
        assert!(
            stderr.is_empty(),
            "clean {runtime} station wrote stderr: {stderr}"
        );
        assert!(stdout.contains("\"event\":\"station_exit\""));
        assert!(stdout.contains("\"outcome\":\"clean\""));
        assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
        assert!(stdout.contains("\"drain_timed_out\":false"));
        remove_tree(&profiles).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_denies_active_task_capabilities_by_default_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-restricted-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-restricted-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create restricted E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd_with_task_permissions(
        stationd,
        &pipe_name,
        &profiles,
        false,
    );
    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid restricted client config"),
    )
    .await
    .expect("connect restricted task client");
    let interactive_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/restricted-interaction"),
        },
        TaskStep::ClickSelector {
            selector: "main".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid restricted interaction task");
    assert!(matches!(
        client
            .run_task("restricted-profile", interactive_task)
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    let scripted_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/restricted-script"),
        },
        TaskStep::Evaluate {
            script: "document.title".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid restricted script task");
    assert!(matches!(
        client.run_task("restricted-profile", scripted_task).await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert!(matches!(
        client
            .update_identity_state(
                "restricted-profile",
                SessionStateUpdate {
                    phase: SessionPhase::ReauthRequired,
                    expires_at_unix_ms: None,
                },
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert!(matches!(
        client.identity_status("restricted-profile").await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert!(matches!(
        client
            .begin_auth_session(
                "restricted-auth-profile",
                BrowserPersona::desktop_default(),
                fixture.url("/restricted-auth"),
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    assert!(matches!(
        client
            .check_auth_session(
                "restricted-auth-profile",
                BrowserPersona::desktop_default(),
                SessionHealthProbe {
                    url: fixture.url("/restricted-health"),
                    ready_selector: "[data-session-ready]".to_owned(),
                    reauth_selector: "[data-session-reauth]".to_owned(),
                    ready_ttl_seconds: 60,
                },
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    let status = client.status().await.expect("restricted station status");
    assert_eq!(status.resident_identities, 0);
    client.shutdown().await.expect("shutdown restricted station");
    let exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("restricted daemon exit timeout")
        .expect("wait for restricted daemon");
    assert!(exit.success(), "restricted station failed: {exit}");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "restricted station wrote stderr: {stderr}");
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_headful_auth_reuses_profile_without_exporting_secrets_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-auth-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-auth-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create headful auth E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let auth_cli = env!("CARGO_BIN_EXE_dig2browser-auth");
    let mut daemon = spawn_stationd_with_headful_auth(
        stationd,
        &pipe_name,
        &profiles,
    );
    let client = StationClient::connect(
        ClientConfig::new(
            &pipe_name,
            Duration::from_secs(15),
            Duration::from_secs(90),
        )
        .expect("valid headful auth client config"),
    )
    .await
    .expect("connect headful auth client");
    let profile_id = "headful-auth-profile";
    let persona = BrowserPersona::desktop_default();

    let auth_url = fixture.url("/auth-bootstrap");
    let begin = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["begin", "--profile-id", profile_id, "--url", &auth_url],
    )
    .await;
    assert!(begin.status.success(), "auth CLI begin failed: {begin:?}");
    assert!(String::from_utf8_lossy(&begin.stdout).contains("\"state\":\"open\""));
    let during = client.status().await.expect("read auth session status");
    assert_eq!(during.resident_identities, 1);
    assert_eq!(during.ready_workers, 1);
    let reauth = client
        .identity_status(profile_id)
        .await
        .expect("read session state after auth start");
    assert_eq!(reauth.phase, SessionPhase::ReauthRequired);
    assert_eq!(reauth.profile_class, Some(ProfileClass::Authenticated));

    let busy_task = CollectionTask::new(vec![TaskStep::Navigate {
        url: fixture.url("/auth-busy"),
    }])
    .expect("valid busy task");
    assert!(matches!(
        client
            .run_task_with_identity(
                profile_id,
                ProfileClass::Authenticated,
                persona.clone(),
                busy_task,
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Unavailable,
            ..
        })
    ));
    assert!(matches!(
        client
            .begin_auth_session(
                profile_id,
                persona.clone(),
                fixture.url("/auth-duplicate"),
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Unavailable,
            ..
        })
    ));

    tokio::time::sleep(Duration::from_millis(500)).await;

    let finish = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["finish", "--profile-id", profile_id],
    )
    .await;
    assert!(finish.status.success(), "auth CLI finish failed: {finish:?}");
    assert!(String::from_utf8_lossy(&finish.stdout).contains("\"state\":\"closed\""));
    assert!(matches!(
        client.finish_auth_session(profile_id).await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));

    let verification = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/auth-check"),
        },
        TaskStep::Evaluate {
            script: "localStorage.getItem('dig2browser_auth_e2e')".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid post-auth verification task");
    let result = client
        .run_task_with_identity(
            profile_id,
            ProfileClass::Authenticated,
            persona,
            verification,
        )
        .await
        .expect("reuse authenticated profile in headless worker");
    assert_eq!(
        result.replies()[1],
        TaskReply::ScriptJson("\"present\"".to_owned())
    );
    let TaskReply::Capture(capture) = &result.replies()[2] else {
        panic!("post-auth task did not return evidence capture");
    };
    assert_eq!(capture.requested_url, fixture.url("/auth-check"));
    assert_eq!(capture.final_url, fixture.url("/auth-check"));
    assert!(!format!("{:?}", result.replies()).contains("cookie-secret"));

    let ready_url = fixture.url("/session-ready");
    let health_ready = run_auth_cli(
        auth_cli,
        &pipe_name,
        &[
            "check",
            "--profile-id",
            profile_id,
            "--url",
            &ready_url,
            "--ready-selector",
            "[data-session-ready]",
            "--reauth-selector",
            "[data-session-reauth]",
            "--ready-ttl-seconds",
            "60",
        ],
    )
    .await;
    assert!(health_ready.status.success(), "ready probe failed: {health_ready:?}");
    assert!(String::from_utf8_lossy(&health_ready.stdout).contains("\"phase\":\"ready\""));
    let ready_status = client
        .identity_status(profile_id)
        .await
        .expect("read health-ready state");
    assert_eq!(ready_status.phase, SessionPhase::Ready);
    assert!(ready_status.expires_at_unix_ms.is_some());

    let reauth_url = fixture.url("/session-reauth");
    let health_reauth = run_auth_cli(
        auth_cli,
        &pipe_name,
        &[
            "check",
            "--profile-id",
            profile_id,
            "--url",
            &reauth_url,
            "--ready-selector",
            "[data-session-ready]",
            "--reauth-selector",
            "[data-session-reauth]",
            "--ready-ttl-seconds",
            "60",
        ],
    )
    .await;
    assert!(health_reauth.status.success(), "reauth probe failed: {health_reauth:?}");
    assert!(String::from_utf8_lossy(&health_reauth.stdout)
        .contains("\"phase\":\"reauth_required\""));
    let reauth_status = client
        .identity_status(profile_id)
        .await
        .expect("read health-reauth state");
    assert_eq!(reauth_status.phase, SessionPhase::ReauthRequired);
    assert_eq!(reauth_status.expires_at_unix_ms, None);

    let ready_command = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["ready", "--profile-id", profile_id, "--ttl-seconds", "60"],
    )
    .await;
    assert!(
        ready_command.status.success(),
        "auth CLI ready failed: {ready_command:?}"
    );
    let ready = client
        .identity_status(profile_id)
        .await
        .expect("read ready state after operator confirmation");
    assert_eq!(ready.phase, SessionPhase::Ready);
    assert!(ready.expires_at_unix_ms.is_some_and(|expiry| expiry > unix_time_ms()));
    let status_command = run_auth_cli(
        auth_cli,
        &pipe_name,
        &["status", "--profile-id", profile_id],
    )
    .await;
    assert!(status_command.status.success(), "auth CLI status failed: {status_command:?}");
    assert!(String::from_utf8_lossy(&status_command.stdout).contains("\"phase\":\"ready\""));

    client.shutdown().await.expect("shutdown headful auth station");
    let exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("headful auth daemon exit timeout")
        .expect("wait for headful auth daemon");
    assert!(exit.success(), "headful auth station failed: {exit}");
    let (_, stderr) = read_child_output(&mut daemon).await;
    assert!(stderr.is_empty(), "headful auth station wrote stderr: {stderr}");
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_persists_authenticated_session_lifecycle_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-session-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!(
        "dig2browser-stationd-session-e2e-{unique}"
    ));
    std::fs::create_dir_all(&profiles).expect("create session E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid session client config");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);
    let client = StationClient::connect(client_config.clone())
        .await
        .expect("connect authenticated session client");
    let task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/authenticated-profile"),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid authenticated identity task");
    let result = client
        .run_task_with_identity(
            "authenticated-durable-profile",
            ProfileClass::Authenticated,
            BrowserPersona::desktop_default(),
            task,
        )
        .await
        .expect("create authenticated browser identity");
    assert!(matches!(result.replies()[1], TaskReply::Capture(_)));

    let unknown = client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read initial authenticated state");
    assert_eq!(unknown.profile_class, Some(ProfileClass::Authenticated));
    assert_eq!(unknown.phase, SessionPhase::Unknown);
    assert!(unknown.profile_exists);
    assert!(unknown.persona_bound);
    let expiry = unix_time_ms().saturating_add(1_500);
    client
        .update_identity_state(
            "authenticated-durable-profile",
            SessionStateUpdate {
                phase: SessionPhase::Ready,
                expires_at_unix_ms: Some(expiry),
            },
        )
        .await
        .expect("mark authenticated session ready");
    let ready = client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read ready authenticated state");
    assert_eq!(ready.phase, SessionPhase::Ready);
    assert_eq!(ready.expires_at_unix_ms, Some(expiry));
    assert!(ready.updated_at_unix_ms > 0);

    client.shutdown().await.expect("shutdown first session station");
    let first_exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("first session daemon exit timeout")
        .expect("wait for first session daemon");
    assert!(first_exit.success(), "first session station failed: {first_exit}");
    let (_, first_stderr) = read_child_output(&mut daemon).await;
    assert!(first_stderr.is_empty(), "session station wrote stderr: {first_stderr}");

    let mut successor = spawn_stationd(stationd, &pipe_name, &profiles);
    let successor_client = StationClient::connect(client_config)
        .await
        .expect("connect session successor client");
    let now = unix_time_ms();
    if expiry >= now {
        tokio::time::sleep(Duration::from_millis(
            expiry.saturating_sub(now).saturating_add(25),
        ))
        .await;
    }
    let expired = successor_client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read expired state after restart");
    assert_eq!(expired.phase, SessionPhase::Expired);
    assert_eq!(expired.expires_at_unix_ms, Some(expiry));

    successor_client
        .update_identity_state(
            "authenticated-durable-profile",
            SessionStateUpdate {
                phase: SessionPhase::ReauthRequired,
                expires_at_unix_ms: None,
            },
        )
        .await
        .expect("mark authenticated session for reauthentication");
    let reauth = successor_client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read reauthentication state");
    assert_eq!(reauth.phase, SessionPhase::ReauthRequired);
    assert_eq!(reauth.expires_at_unix_ms, None);

    let renewed_expiry = unix_time_ms().saturating_add(60_000);
    successor_client
        .update_identity_state(
            "authenticated-durable-profile",
            SessionStateUpdate {
                phase: SessionPhase::Ready,
                expires_at_unix_ms: Some(renewed_expiry),
            },
        )
        .await
        .expect("mark reauthenticated session ready");
    let renewed = successor_client
        .identity_status("authenticated-durable-profile")
        .await
        .expect("read renewed session state");
    assert_eq!(renewed.phase, SessionPhase::Ready);
    assert_eq!(renewed.expires_at_unix_ms, Some(renewed_expiry));

    let public_task = CollectionTask::new(vec![TaskStep::Navigate {
        url: fixture.url("/public-profile"),
    }])
    .expect("valid public identity task");
    successor_client
        .run_task("public-session-profile", public_task)
        .await
        .expect("create public browser identity");
    assert!(matches!(
        successor_client
            .update_identity_state(
                "public-session-profile",
                SessionStateUpdate {
                    phase: SessionPhase::Ready,
                    expires_at_unix_ms: Some(renewed_expiry),
                },
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));

    let journal = std::fs::read(
        profiles
            .join("authenticated-durable-profile")
            .join(".dig2browser-session-state-v1"),
    )
    .expect("read non-secret session journal");
    assert_eq!(journal.len() % IdentitySessionStatus::ENCODED_LEN, 0);
    assert_eq!(journal.len(), IdentitySessionStatus::ENCODED_LEN * 3);
    let class = std::fs::read_to_string(
        profiles
            .join("authenticated-durable-profile")
            .join(".dig2browser-profile-class-v1"),
    )
    .expect("read identity class binding");
    assert_eq!(class, "Authenticated");

    successor_client
        .shutdown()
        .await
        .expect("shutdown session successor");
    let successor_exit = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("session successor exit timeout")
        .expect("wait for session successor");
    assert!(successor_exit.success(), "session successor failed: {successor_exit}");
    let (_, successor_stderr) = read_child_output(&mut successor).await;
    assert!(
        successor_stderr.is_empty(),
        "session successor wrote stderr: {successor_stderr}"
    );
    remove_tree(&profiles).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_persists_mobile_persona_and_profile_state_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-mobile-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-stationd-mobile-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create mobile E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let persona = BrowserPersona::mobile(MobilePersonaConfig {
        width: 412,
        height: 915,
        device_scale_milli: 2625,
        max_touch_points: 5,
        locale: "ru-RU".to_owned(),
        timezone: Some("Europe/Moscow".to_owned()),
        platform_version: "14.0.0".to_owned(),
        model: "Pixel 8".to_owned(),
    })
    .expect("valid mobile E2E persona");
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid mobile client config");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);
    let client = StationClient::connect(client_config.clone())
        .await
        .expect("connect mobile persona client");
    let first_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/mobile-first"),
        },
        TaskStep::Evaluate {
            script: "localStorage.setItem('dig2browser_e2e', 'persisted'); ({layoutWidth: innerWidth, layoutHeight: innerHeight, screenWidth: screen.width, screenHeight: screen.height, dpr: devicePixelRatio, touch: navigator.maxTouchPoints, ua: navigator.userAgent, uaMobile: navigator.userAgentData && navigator.userAgentData.mobile, uaPlatform: navigator.userAgentData && navigator.userAgentData.platform, platform: navigator.platform, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, marker: localStorage.getItem('dig2browser_e2e')})".to_owned(),
        },
        TaskStep::Capture {
            policy: TaskCapturePolicy::EvidenceViewport,
        },
    ])
    .expect("valid first mobile task");
    let first_result = client
        .run_task_with_persona("mobile-durable-profile", persona.clone(), first_task)
        .await
        .expect("run first mobile persona task");
    let TaskReply::ScriptJson(first_fingerprint) = &first_result.replies()[1] else {
        panic!("first mobile task did not return fingerprint JSON");
    };
    assert_mobile_fingerprint(first_fingerprint, true);
    client.shutdown().await.expect("shutdown first mobile station");
    let first_exit = tokio::time::timeout(Duration::from_secs(30), daemon.wait())
        .await
        .expect("first mobile daemon exit timeout")
        .expect("wait for first mobile daemon");
    assert!(first_exit.success(), "first mobile station failed: {first_exit}");
    let (_, first_stderr) = read_child_output(&mut daemon).await;
    assert!(first_stderr.is_empty(), "mobile station wrote stderr: {first_stderr}");

    let mut successor = spawn_stationd(stationd, &pipe_name, &profiles);
    let successor_client = StationClient::connect(client_config)
        .await
        .expect("connect mobile successor client");
    let second_task = CollectionTask::new(vec![
        TaskStep::Navigate {
            url: fixture.url("/mobile-second"),
        },
        TaskStep::Evaluate {
            script: "({layoutWidth: innerWidth, layoutHeight: innerHeight, screenWidth: screen.width, screenHeight: screen.height, dpr: devicePixelRatio, touch: navigator.maxTouchPoints, ua: navigator.userAgent, uaMobile: navigator.userAgentData && navigator.userAgentData.mobile, uaPlatform: navigator.userAgentData && navigator.userAgentData.platform, platform: navigator.platform, language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, marker: localStorage.getItem('dig2browser_e2e')})".to_owned(),
        },
    ])
    .expect("valid second mobile task");
    let second_result = successor_client
        .run_task_with_persona("mobile-durable-profile", persona, second_task)
        .await
        .expect("run successor mobile persona task");
    let TaskReply::ScriptJson(second_fingerprint) = &second_result.replies()[1] else {
        panic!("second mobile task did not return fingerprint JSON");
    };
    assert_mobile_fingerprint(second_fingerprint, true);

    let mismatch_task = CollectionTask::new(vec![TaskStep::Navigate {
        url: fixture.url("/persona-mismatch"),
    }])
    .expect("valid persona mismatch task");
    assert!(matches!(
        successor_client
            .run_task_with_persona(
                "mobile-durable-profile",
                BrowserPersona::desktop_default(),
                mismatch_task,
            )
            .await,
        Err(ClientError::Remote {
            status: ResponseStatus::Invalid,
            ..
        })
    ));
    let manifest = profiles
        .join("mobile-durable-profile")
        .join(".dig2browser-persona-v1");
    let manifest_text = std::fs::read_to_string(manifest).expect("read persona manifest");
    assert!(manifest_text.contains("kind=Mobile"));
    assert!(!manifest_text.contains("persisted"));

    successor_client
        .shutdown()
        .await
        .expect("shutdown mobile successor");
    let successor_exit = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("mobile successor exit timeout")
        .expect("wait for mobile successor");
    assert!(successor_exit.success(), "mobile successor failed: {successor_exit}");
    let (_, successor_stderr) = read_child_output(&mut successor).await;
    assert!(
        successor_stderr.is_empty(),
        "mobile successor wrote stderr: {successor_stderr}"
    );
    remove_tree(&profiles).await;
}

fn assert_mobile_fingerprint(fingerprint: &str, marker_expected: bool) {
    for expected in [
        "\"screenWidth\":412",
        "\"screenHeight\":915",
        "\"dpr\":2.625",
        "\"touch\":5",
        "\"uaMobile\":true",
        "\"uaPlatform\":\"Android\"",
        "\"platform\":\"Android\"",
        "\"language\":\"ru-RU\"",
        "\"timezone\":\"Europe/Moscow\"",
        "Android 14.0.0; Pixel 8",
    ] {
        assert!(
            fingerprint.contains(expected),
            "mobile fingerprint omitted {expected}: {fingerprint}"
        );
    }
    assert_eq!(
        fingerprint.contains("\"marker\":\"persisted\""),
        marker_expected,
        "unexpected durable marker state: {fingerprint}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stationd_hard_kill_releases_profile_and_client_reconnects_e2e() {
    let _serial = e2e_serial_guard().await;
    let fixture = FixtureServer::start();
    let unique = uuid::Uuid::new_v4();
    let pipe_name = format!("dig2browser-stationd-crash-e2e-{unique}");
    let profiles = e2e_temp_base().join(format!("dig2browser-stationd-crash-e2e-{unique}"));
    std::fs::create_dir_all(&profiles).expect("create crash E2E profiles root");
    let stationd = env!("CARGO_BIN_EXE_dig2browser-stationd");
    let mut daemon = spawn_stationd(stationd, &pipe_name, &profiles);
    let client_config = ClientConfig::new(
        &pipe_name,
        Duration::from_secs(15),
        Duration::from_secs(90),
    )
    .expect("valid crash E2E client config");
    let client = StationClient::connect(client_config)
        .await
        .expect("connect crash E2E client");
    let external_profile =
        ProfileOwnershipGuard::acquire(profiles.join("externally-locked-profile"))
            .expect("lock profile outside station");
    assert!(
        client
            .capture(
                "externally-locked-profile",
                fixture.url("/while-profile-locked"),
            )
            .await
            .is_err(),
        "station unexpectedly acquired an externally locked profile"
    );
    drop(external_profile);
    let released_capture = client
        .capture(
            "externally-locked-profile",
            fixture.url("/after-profile-release"),
        )
        .await
        .expect("station acquires profile after external owner releases it");
    assert_eq!(released_capture.title.as_deref(), Some("after-profile-release"));
    client
        .capture("crash-recovery-profile", fixture.url("/before-crash"))
        .await
        .expect("capture before stationd crash");

    daemon.kill().await.expect("hard-kill station daemon");
    daemon.wait().await.expect("reap killed station daemon");
    let mut successor = spawn_stationd(stationd, &pipe_name, &profiles);

    assert!(
        client.health().await.is_err(),
        "stale transport unexpectedly survived stationd hard kill"
    );
    client
        .health()
        .await
        .expect("client reconnects to successor stationd");
    let fresh = client.status().await.expect("read successor baseline status");
    assert_eq!(fresh.resident_identities, 0);
    assert_eq!(fresh.captures_started, 0);
    assert_eq!(fresh.captures_succeeded, 0);
    assert_eq!(fresh.captures_failed, 0);
    assert!(fresh.accepted_connections >= 1);
    let capture = client
        .capture("crash-recovery-profile", fixture.url("/after-crash"))
        .await
        .expect("successor acquires profile released by hard kill");
    assert_eq!(capture.title.as_deref(), Some("after-crash"));
    assert!(
        String::from_utf8_lossy(&capture.html)
            .contains("data-daemon-e2e=\"after-crash\"")
    );
    let recovered = client.status().await.expect("read successor capture status");
    assert_eq!(recovered.resident_identities, 1);
    assert_eq!(recovered.captures_started, 1);
    assert_eq!(recovered.captures_succeeded, 1);
    assert_eq!(recovered.captures_failed, 0);
    client.shutdown().await.expect("shutdown successor stationd");
    let status = tokio::time::timeout(Duration::from_secs(30), successor.wait())
        .await
        .expect("successor stationd exit timeout")
        .expect("wait for successor stationd");
    assert!(status.success(), "successor stationd failed: {status}");
    let (stdout, stderr) = read_child_output(&mut successor).await;
    assert!(stderr.is_empty(), "clean successor wrote stderr: {stderr}");
    assert!(stdout.contains("\"outcome\":\"clean\""));
    assert!(stdout.contains("\"stop_reason\":\"remote_request\""));
    remove_tree(&profiles).await;
}

async fn wait_for_status(
    client: &StationClient,
    predicate: impl Fn(&StationStatus) -> bool,
) -> StationStatus {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let status = client.status().await.expect("poll station status");
        if predicate(&status) {
            return status;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "station status predicate timed out: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn e2e_serial_guard() -> tokio::sync::SemaphorePermit<'static> {
    static E2E_SERIAL: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    E2E_SERIAL
        .acquire()
        .await
        .expect("daemon E2E semaphore remains open")
}

async fn read_child_output(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut stream) = child.stdout.take() {
        stream
            .read_to_string(&mut stdout)
            .await
            .expect("read station stdout");
    }
    let mut stderr = String::new();
    if let Some(mut stream) = child.stderr.take() {
        stream
            .read_to_string(&mut stderr)
            .await
            .expect("read station stderr");
    }
    (stdout, stderr)
}

async fn run_auth_cli(
    auth_cli: &str,
    pipe_name: &str,
    args: &[&str],
) -> std::process::Output {
    let mut command = tokio::process::Command::new(auth_cli);
    command.args(["--pipe-name", pipe_name]);
    command.args(args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run dig2browser-auth CLI")
}

fn spawn_stationd(stationd: &str, pipe_name: &str, profiles: &Path) -> tokio::process::Child {
    spawn_stationd_with_permissions(stationd, pipe_name, profiles, true, true, false)
}

fn spawn_stationd_for_runtime(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    runtime: &str,
) -> tokio::process::Child {
    spawn_stationd_with_runtime_permissions(
        stationd,
        pipe_name,
        profiles,
        Some(runtime),
        true,
        true,
        false,
    )
}

fn spawn_stationd_with_task_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    allow_active_tasks: bool,
) -> tokio::process::Child {
    spawn_stationd_with_permissions(
        stationd,
        pipe_name,
        profiles,
        allow_active_tasks,
        false,
        false,
    )
}

fn spawn_stationd_with_headful_auth(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
) -> tokio::process::Child {
    spawn_stationd_with_permissions(stationd, pipe_name, profiles, true, true, true)
}

fn spawn_stationd_with_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    allow_active_tasks: bool,
    allow_session_state_updates: bool,
    allow_headful_auth: bool,
) -> tokio::process::Child {
    spawn_stationd_with_runtime_permissions(
        stationd,
        pipe_name,
        profiles,
        None,
        allow_active_tasks,
        allow_session_state_updates,
        allow_headful_auth,
    )
}

fn spawn_stationd_with_runtime_permissions(
    stationd: &str,
    pipe_name: &str,
    profiles: &Path,
    runtime: Option<&str>,
    allow_active_tasks: bool,
    allow_session_state_updates: bool,
    allow_headful_auth: bool,
) -> tokio::process::Child {
    let mut command = tokio::process::Command::new(stationd);
    command.args([
            "--pipe-name",
            pipe_name,
            "--profiles-root",
            profiles.to_str().expect("profiles path is UTF-8"),
            "--max-resident",
            "2",
            "--max-in-flight",
            "4",
            "--max-connections",
            "8",
            "--timeout-seconds",
            "60",
            "--drain-seconds",
            "15",
            "--allow-remote-shutdown",
        ]);
    if let Some(runtime) = runtime {
        command.args(["--runtime", runtime]);
    }
    if allow_active_tasks {
        command.args(["--allow-interactive-tasks", "--allow-scripted-tasks"]);
    }
    if allow_session_state_updates {
        command.args([
            "--allow-identity-status",
            "--allow-session-state-updates",
        ]);
    }
    if allow_headful_auth {
        command.args(["--allow-headful-auth", "--allow-session-health"]);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn station daemon")
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
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
    panic!("could not remove stationd E2E profiles: {}", path.display());
}

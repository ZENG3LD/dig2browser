#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use dig2browser::browser::StealthBrowser;
use dig2browser::detect::{
    detect_browser, BrowserPreference, BrowserProfile, LaunchConfig,
};
use dig2browser::stealth::StealthConfig;
use dig2browser::{
    BrowserProcessIsolation, WindowsBrowserRuntimeMirror, WindowsRuntimeMirrorScope,
};

#[test]
fn runtime_mirror_scope_normalizes_equivalent_windows_paths() {
    let first = WindowsRuntimeMirrorScope::for_profiles_root(Path::new(
        r"\\?\C:\Profiles\Operator\",
    ));
    let equivalent = WindowsRuntimeMirrorScope::for_profiles_root(Path::new(
        "c:/profiles/operator",
    ));
    assert_eq!(first, equivalent);
    assert_eq!(first.as_hex().len(), 64);
}

#[test]
fn runtime_mirror_scope_rejects_malformed_wire_values() {
    let valid = WindowsRuntimeMirrorScope::for_profiles_root(Path::new(r"C:\Profiles"));
    assert_eq!(valid.as_hex().parse(), Ok(valid));
    let malformed_values = vec![
        String::new(),
        "0".to_owned(),
        "0a".to_owned(),
        "a".repeat(63),
        "a".repeat(65),
        format!("{}G", "a".repeat(63)),
        "A".repeat(64),
    ];
    for malformed in malformed_values {
        assert!(
            malformed.parse::<WindowsRuntimeMirrorScope>().is_err(),
            "accepted malformed scope: {malformed}"
        );
    }
}

fn e2e_root() -> PathBuf {
    let base = std::env::var_os("DIG2BROWSER_E2E_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\tmp"));
    base.join(format!(
        "dig2browser-runtime-mirror-e2e-{}",
        uuid::Uuid::new_v4()
    ))
}

async fn remove_tree(path: &Path) {
    for _ in 0..100 {
        match tokio::fs::remove_dir_all(path).await {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    panic!("could not remove runtime-mirror E2E tree: {}", path.display());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires installed user-local Chrome and an NTFS volume supporting hardlinks"]
async fn station_owned_runtime_mirror_launches_real_chrome_over_cdp_pipe_e2e() {
    let source = detect_browser(BrowserPreference::ChromeOnly)
        .expect("detect installed Chrome");
    let root = e2e_root();
    let profiles_root = root.join("profiles");
    let browser_profile = profiles_root.join("browser");
    std::fs::create_dir_all(&profiles_root).expect("create E2E profiles root");

    let mirror = WindowsBrowserRuntimeMirror::materialize(&source, &profiles_root)
        .expect("materialize station-owned Chrome runtime mirror");
    let mirror_root = mirror.root().to_path_buf();
    let source_path = std::fs::canonicalize(&source.path)
        .unwrap_or_else(|_| source.path.clone());
    let mirror_path = std::fs::canonicalize(&mirror.browser_binary().path)
        .unwrap_or_else(|_| mirror.browser_binary().path.clone());
    assert_ne!(
        source_path, mirror_path,
        "runtime mirror resolved to the installed Chrome path"
    );
    assert!(
        mirror_path
            .to_string_lossy()
            .to_ascii_lowercase()
            .contains(r"dig2browser\runtime-mirrors"),
        "runtime mirror is outside the owned mirror catalog: {}",
        mirror_path.display()
    );

    let launch = LaunchConfig {
        browser_pref: BrowserPreference::ChromeOnly,
        headless: true,
        profile: BrowserProfile::Persistent(browser_profile),
        ..LaunchConfig::default()
    };
    let browser = StealthBrowser::launch_with_process_isolation(
        launch,
        StealthConfig::default(),
        BrowserProcessIsolation::WindowsRuntimeMirror(
            mirror.browser_binary().clone(),
        ),
    )
    .await
    .expect("launch mirrored Chrome through owned CDP pipes");
    let page = browser
        .new_blank_page()
        .await
        .expect("create mirrored Chrome page");
    let user_agent = page
        .eval("navigator.userAgent")
        .await
        .expect("evaluate in mirrored Chrome");
    assert!(
        user_agent.as_str().is_some_and(|value| value.contains("Chrome")),
        "mirrored runtime did not execute Chrome: {user_agent}"
    );
    drop(page);
    browser.close().await.expect("close mirrored Chrome");
    mirror.remove().expect("remove the closed runtime mirror");
    assert!(!mirror_root.exists(), "runtime mirror survived explicit removal");
    remove_tree(&root).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires installed user-local Chrome and an NTFS volume supporting hardlinks"]
async fn scoped_runtime_mirror_reuses_and_inspects_real_chrome_e2e() {
    let source = detect_browser(BrowserPreference::ChromeOnly)
        .expect("detect installed Chrome");
    let root = e2e_root();
    let profiles_root = root.join("profiles");
    std::fs::create_dir_all(&profiles_root).expect("create E2E profiles root");
    let canonical_profiles = std::fs::canonicalize(&profiles_root)
        .expect("canonicalize E2E profiles root");
    let scope = WindowsRuntimeMirrorScope::for_profiles_root(&canonical_profiles);

    let first = WindowsBrowserRuntimeMirror::materialize_scoped(&source, scope)
        .expect("materialize scoped Chrome runtime mirror");
    let first_root = first.root().to_path_buf();
    let reused = WindowsBrowserRuntimeMirror::materialize_scoped(&source, scope)
        .expect("reuse scoped Chrome runtime mirror");
    assert_eq!(first.root(), reused.root());
    assert_eq!(first.browser_binary().path, reused.browser_binary().path);
    assert_eq!(first.executable_paths(), reused.executable_paths());

    let inspected = WindowsBrowserRuntimeMirror::inspect(&first_root)
        .expect("inspect reused scoped Chrome runtime mirror");
    assert_eq!(inspected.browser_binary().path, first.browser_binary().path);
    assert_eq!(inspected.executable_paths(), first.executable_paths());
    drop(first);
    drop(inspected);
    reused.remove().expect("remove scoped Chrome runtime mirror");
    assert!(!first_root.exists(), "scoped runtime mirror survived removal");
    remove_tree(&root).await;
}

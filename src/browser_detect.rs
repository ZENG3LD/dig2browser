use crate::error::BrowserError;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BrowserPreference {
    #[default]
    Auto,
    ChromeOnly,
    EdgeOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Edge,
    Chromium,
}

#[derive(Debug, Clone)]
pub struct BrowserBinary {
    pub path: PathBuf,
    pub kind: BrowserKind,
}

pub fn detect_browser(pref: BrowserPreference) -> Result<BrowserBinary, BrowserError> {
    let mut tried = Vec::new();

    let chrome_paths = get_chrome_paths();
    let edge_paths = get_edge_paths();

    let search_order: Vec<(Vec<String>, BrowserKind)> = match pref {
        BrowserPreference::Auto => vec![
            (chrome_paths, BrowserKind::Chrome),
            (edge_paths, BrowserKind::Edge),
        ],
        BrowserPreference::ChromeOnly => vec![(chrome_paths, BrowserKind::Chrome)],
        BrowserPreference::EdgeOnly => vec![(edge_paths, BrowserKind::Edge)],
    };

    for (paths, kind) in search_order {
        for path_str in paths {
            let path = PathBuf::from(&path_str);
            tried.push(path_str);
            if path.exists() {
                return Ok(BrowserBinary { path, kind });
            }
        }
    }

    Err(BrowserError::BinaryNotFound { tried })
}

fn get_chrome_paths() -> Vec<String> {
    let mut paths = Vec::new();

    if let Ok(v) = std::env::var("CHROME_PATH") {
        paths.push(v);
    }

    if cfg!(target_os = "windows") {
        paths.push(r"C:\Program Files\Google\Chrome\Application\chrome.exe".into());
        paths.push(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe".into());
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            paths.push(format!(r"{}\Google\Chrome\Application\chrome.exe", local));
        }
    } else if cfg!(target_os = "macos") {
        paths.push("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into());
    } else {
        paths.push("/usr/bin/google-chrome".into());
        paths.push("/usr/bin/chromium".into());
        paths.push("/usr/bin/chromium-browser".into());
    }

    paths
}

fn get_edge_paths() -> Vec<String> {
    let mut paths = Vec::new();

    if let Ok(v) = std::env::var("EDGE_PATH") {
        paths.push(v);
    }

    if cfg!(target_os = "windows") {
        paths.push(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".into());
        paths.push(r"C:\Program Files\Microsoft\Edge\Application\msedge.exe".into());
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            paths.push(format!(r"{}\Microsoft\Edge\Application\msedge.exe", local));
        }
    }

    paths
}

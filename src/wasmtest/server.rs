//! Minimal static HTTP server for serving wasm shim files to the browser.

use std::{
    fs,
    path::PathBuf,
    sync::Arc,
    thread::{self, JoinHandle},
};

use tiny_http::{Header, Response, Server};

use super::WasmTestError;

/// A running static file server.
///
/// Dropped when the `StaticServer` is dropped — `Drop` calls `server.unblock()`
/// which causes `incoming_requests()` to terminate, then joins the thread.
pub struct StaticServer {
    /// Port the server is listening on.
    pub port: u16,
    server: Arc<Server>,
    handle: Option<JoinHandle<()>>,
}

/// Serve `dir` as a static HTTP root on a random available port.
///
/// Returns a `StaticServer` whose `url()` points at the root.
pub fn serve(dir: PathBuf) -> Result<StaticServer, WasmTestError> {
    let server =
        Server::http("127.0.0.1:0").map_err(|e| WasmTestError::Server(e.to_string()))?;

    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .ok_or_else(|| WasmTestError::Server("non-IP listen addr".to_string()))?;

    let server = Arc::new(server);
    let server_clone = Arc::clone(&server);
    let dir_clone = dir.clone();

    let handle = thread::spawn(move || {
        serve_loop(&server_clone, &dir_clone);
    });

    Ok(StaticServer {
        port,
        server,
        handle: Some(handle),
    })
}

fn serve_loop(server: &Server, dir: &PathBuf) {
    for request in server.incoming_requests() {
        let url_path = request.url().to_string();

        // Map "/" → "index.html", strip leading "/".
        let rel_path = if url_path == "/" {
            "index.html".to_string()
        } else {
            url_path.trim_start_matches('/').to_string()
        };

        // Sanitize: reject path traversal.
        if rel_path.split('/').any(|seg| seg == ".." || seg.starts_with('/')) {
            let response = Response::from_string("403 Forbidden").with_status_code(403);
            if let Err(e) = request.respond(response) {
                tracing::warn!("server: respond 403 error: {e}");
            }
            continue;
        }

        let file_path = dir.join(&rel_path);

        // Guard against escaping the serve root via symlinks / canonical path.
        let canonical_dir = match fs::canonicalize(dir) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("server: cannot canonicalize dir {dir:?}: {e}");
                continue;
            }
        };
        let canonical_file = match fs::canonicalize(&file_path) {
            Ok(p) => p,
            Err(_) => {
                // File doesn't exist or can't be canonicalized → 404.
                let response = Response::from_string("404 Not Found").with_status_code(404);
                if let Err(e) = request.respond(response) {
                    tracing::warn!("server: respond 404 error: {e}");
                }
                continue;
            }
        };
        if !canonical_file.starts_with(&canonical_dir) {
            let response = Response::from_string("403 Forbidden").with_status_code(403);
            if let Err(e) = request.respond(response) {
                tracing::warn!("server: respond 403 error: {e}");
            }
            continue;
        }

        let bytes = match fs::read(&canonical_file) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!("server: read {canonical_file:?}: {e}");
                let response = Response::from_string("500 Internal Server Error")
                    .with_status_code(500);
                if let Err(re) = request.respond(response) {
                    tracing::warn!("server: respond 500 error: {re}");
                }
                continue;
            }
        };

        let ctype = content_type(&rel_path);
        let header = match Header::from_bytes("Content-Type", ctype) {
            Ok(h) => h,
            Err(_) => {
                tracing::warn!("server: invalid Content-Type header value for {rel_path:?}");
                continue;
            }
        };

        let response = Response::from_data(bytes)
            .with_header(header)
            .with_status_code(200);

        if let Err(e) = request.respond(response) {
            tracing::warn!("server: respond error for {rel_path:?}: {e}");
        }
    }
}

/// Map file extension to MIME type.
///
/// `.wasm` and `.js`/`.mjs` must use the correct MIME — browsers reject them
/// otherwise.
fn content_type(path: &str) -> &'static str {
    if path.ends_with(".html") || path.ends_with(".htm") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".js") || path.ends_with(".mjs") {
        "application/javascript"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else if path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

impl StaticServer {
    /// Base URL of the server, e.g. `http://127.0.0.1:54321`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }
}

impl Drop for StaticServer {
    fn drop(&mut self) {
        // Signal the accept loop to stop.
        self.server.unblock();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

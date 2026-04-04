use crate::{BackendPort, DesktopRuntime, DesktopRuntimeStatus};
use tauri::State;

/// Returns the port the backend is listening on.
#[tauri::command]
pub fn get_backend_port(port: State<BackendPort>) -> u16 {
    port.inner().0.lock().map(|guard| *guard).unwrap_or(5000)
}

/// Returns the current desktop runtime status for diagnostics.
#[tauri::command]
pub fn get_desktop_runtime_status(runtime: State<DesktopRuntime>) -> DesktopRuntimeStatus {
    runtime
        .inner()
        .0
        .lock()
        .map(|state| state.clone())
        .unwrap_or_else(|_| DesktopRuntimeStatus {
            ready: false,
            message: Some("Failed to acquire desktop runtime state.".to_string()),
            log_path: std::env::temp_dir()
                .join("gatestack-desktop.log")
                .to_string_lossy()
                .into_owned(),
        })
}

/// Pings the backend and returns whether it is healthy.
#[tauri::command]
pub async fn check_backend_health(port: State<'_, BackendPort>) -> Result<bool, String> {
    let p = port
        .inner()
        .0
        .lock()
        .map(|guard| *guard)
        .map_err(|_| "Failed to read backend port state".to_string())?;
    let url = format!("http://127.0.0.1:{}/api/auth/status", p);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;

    match client.get(&url).send().await {
        Ok(resp) => Ok(resp.status().as_u16() < 500),
        Err(_) => Ok(false),
    }
}

/// Returns the current application version from Cargo.toml.
#[tauri::command]
pub fn get_app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Returns the path of the desktop diagnostic log file.
#[tauri::command]
pub fn get_desktop_log_path(runtime: State<DesktopRuntime>) -> String {
    runtime
        .inner()
        .0
        .lock()
        .map(|state| state.log_path.clone())
        .unwrap_or_else(|_| {
            std::env::temp_dir()
                .join("gatestack-desktop.log")
                .to_string_lossy()
                .into_owned()
        })
}

/// Opens the bundled user guide PDF/HTML in the default browser / viewer.
#[tauri::command]
pub async fn open_docs(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    // The guide lives next to the binary as docs/README.html
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let guide = exe
        .parent()
        .ok_or_else(|| "Executable parent directory not found".to_string())?
        .join("docs")
        .join("README.html");
    if guide.exists() {
        app.opener()
            .open_path(guide.to_string_lossy().into_owned(), None::<String>)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

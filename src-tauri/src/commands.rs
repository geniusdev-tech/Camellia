use crate::BackendPort;
use tauri::State;

/// Returns the port the Flask backend is listening on.
#[tauri::command]
pub fn get_backend_port(port: State<BackendPort>) -> u16 {
    *port.0.lock().unwrap()
}

/// Pings the Flask backend and returns whether it is healthy.
#[tauri::command]
pub async fn check_backend_health(port: State<'_, BackendPort>) -> Result<bool, String> {
    let p = *port.0.lock().unwrap();
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

/// Opens the bundled user guide PDF/HTML in the default browser / viewer.
#[tauri::command]
pub async fn open_docs(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_shell::ShellExt;
    // The guide lives next to the binary as docs/README.html
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let guide = exe
        .parent()
        .unwrap()
        .join("docs")
        .join("README.html");
    if guide.exists() {
        app.shell()
            .open(guide.to_string_lossy().as_ref(), None)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

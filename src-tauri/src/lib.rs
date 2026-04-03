pub mod commands;

use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::Mutex,
};
use tauri::State;

pub struct BackendPort(pub Mutex<u16>);
pub struct DesktopRuntime(pub Mutex<DesktopRuntimeStatus>);

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopRuntimeStatus {
    pub ready: bool,
    pub message: Option<String>,
    pub log_path: String,
}

pub struct DesktopLogger {
    path: PathBuf,
}

impl DesktopLogger {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(if cfg!(debug_assertions) {
            "gatestack-desktop-dev.log"
        } else {
            "gatestack-desktop.log"
        });

        Self { path }
    }

    pub fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }

    pub fn log(&self, level: &str, message: impl AsRef<str>) {
        let line = format!("[{}] {}\n", level, message.as_ref());
        let _ = fs::create_dir_all(self.path.parent().unwrap_or_else(|| std::path::Path::new(".")));
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

pub fn set_runtime_status(runtime: &State<'_, DesktopRuntime>, ready: bool, message: Option<String>) {
    if let Ok(mut state) = runtime.inner().0.lock() {
        state.ready = ready;
        state.message = message;
    }
}

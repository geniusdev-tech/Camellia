// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use gatestack_lib::{
    commands, set_runtime_status, BackendPort, DesktopLogger, DesktopRuntime, DesktopRuntimeStatus,
};
use std::{sync::Mutex, time::Duration};
use tauri::{Manager, State};

#[cfg(not(debug_assertions))]
use tauri_plugin_shell::{self, process::CommandEvent, ShellExt};

fn main() {
    let startup_logger = DesktopLogger::new();
    startup_logger.log("INFO", "Starting GateStack desktop runtime");

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(BackendPort(Mutex::new(5000)))
        .manage(DesktopRuntime(Mutex::new(DesktopRuntimeStatus {
            ready: false,
            message: Some("Desktop runtime is still starting.".to_string()),
            log_path: startup_logger.path_string(),
        })))
        .setup(|app| {
            let app_handle = app.handle().clone();
            let port_state: State<BackendPort> = app.state();
            let runtime_state: State<DesktopRuntime> = app.state();
            let logger = DesktopLogger::new();

            let port = determine_port(&logger);
            if let Ok(mut state) = port_state.inner().0.lock() {
                *state = port;
            } else {
                logger.log("ERROR", "Failed to acquire backend port state lock");
            }

            let mut failure_message: Option<String> = None;

            #[cfg(not(debug_assertions))]
            {
                if failure_message.is_none() {
                    match app_handle.shell().sidecar("gatestack-backend") {
                        Ok(port_command) => {
                            let command = port_command
                                .env("PORT", port.to_string())
                                .env("FLASK_ENV", "production")
                                .env("DESKTOP_MODE", "1");
                            match command.spawn() {
                                Ok((mut rx, _child)) => {
                                    let logger = DesktopLogger::new();
                                    tauri::async_runtime::spawn(async move {
                                        while let Some(event) = rx.recv().await {
                                            match event {
                                                CommandEvent::Stdout(line) => {
                                                    logger.log("BACKEND", &String::from_utf8_lossy(&line).trim());
                                                }
                                                CommandEvent::Stderr(line) => {
                                                    logger.log("BACKEND_ERR", &String::from_utf8_lossy(&line).trim());
                                                }
                                                _ => {}
                                            }
                                        }
                                    });
                                }
                                Err(err) => {
                                    let message = format!("Failed to start backend sidecar: {err}");
                                    logger.log("ERROR", &message);
                                    failure_message = Some(message);
                                }
                            }
                        }
                        Err(err) => {
                            let message = format!("Failed to configure backend sidecar: {err}");
                            logger.log("ERROR", &message);
                            failure_message = Some(message);
                        }
                    }
                }
            }

            if failure_message.is_none() {
                if let Err(err) = wait_for_backend(port, &logger) {
                    logger.log("WARN", &err);
                    failure_message = Some(err);
                }
            }

            if let Some(window) = app_handle.get_webview_window("main") {
                #[cfg(not(debug_assertions))]
                {
                    if failure_message.is_none() {
                        let url = format!("http://127.0.0.1:{port}");
                        match url.parse() {
                            Ok(target) => {
                                if let Err(err) = window.navigate(target) {
                                    let message = format!("Failed to navigate desktop window: {err}");
                                    logger.log("ERROR", &message);
                                    failure_message = Some(message);
                                }
                            }
                            Err(err) => {
                                let message = format!("Failed to parse backend URL '{url}': {err}");
                                logger.log("ERROR", &message);
                                failure_message = Some(message);
                            }
                        }
                    } else {
                        logger.log("WARN", "Skipping desktop navigation because backend startup failed.");
                    }
                }
                if let Err(err) = window.show() {
                    let message = format!("Failed to show desktop window: {err}");
                    logger.log("ERROR", &message);
                    failure_message = Some(message);
                }
            } else {
                let message = "Main desktop window was not found.".to_string();
                logger.log("ERROR", &message);
                failure_message = Some(message);
            }

            if let Some(message) = failure_message {
                set_runtime_status(&runtime_state, false, Some(message));
            } else {
                logger.log("INFO", format!("Backend ready on port {port}"));
                set_runtime_status(&runtime_state, true, None);
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_backend_port,
            commands::get_desktop_runtime_status,
            commands::check_backend_health,
            commands::get_app_version,
            commands::get_desktop_log_path,
            commands::open_docs,
        ]);

    let context = tauri::generate_context!();
    if let Err(err) = builder.run(context) {
        startup_logger.log("ERROR", format!("Desktop runtime crashed: {err}"));
        panic!("error while running GateStack: {err}");
    }
}

fn determine_port(logger: &DesktopLogger) -> u16 {
    if let Ok(value) = std::env::var("PORT") {
        if let Ok(parsed) = value.parse::<u16>() {
            return parsed;
        }
        logger.log("WARN", format!("Invalid PORT value '{value}', falling back to default."));
    }
    choose_default_port(logger)
}

fn choose_default_port(logger: &DesktopLogger) -> u16 {
    if cfg!(debug_assertions) {
        5000
    } else {
        match portpicker::pick_unused_port() {
            Some(port) => port,
            None => {
                logger.log("WARN", "Unable to pick an unused port, defaulting to 5000.");
                5000
            }
        }
    }
}

fn wait_for_backend(port: u16, logger: &DesktopLogger) -> Result<(), String> {
    let check_url = format!("http://127.0.0.1:{port}/api/auth/status");
    for attempt in 0..50 {
        std::thread::sleep(Duration::from_millis(200));
        match reqwest::blocking::get(&check_url) {
            Ok(response) => {
                if response.status().is_success() || response.status().as_u16() < 500 {
                    return Ok(());
                }
                logger.log("DEBUG", format!("Health check returned status {}", response.status()));
            }
            Err(err) => {
                logger.log("DEBUG", format!("Health check attempt {attempt} failed: {err}"));
            }
        }
    }
    Err(format!(
        "Backend did not respond in time on http://127.0.0.1:{port}. Check the desktop log at {}",
        logger.path_string()
    ))
}

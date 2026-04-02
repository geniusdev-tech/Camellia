// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;

use std::sync::Mutex;
use tauri::{Manager, State};

pub struct BackendPort(pub Mutex<u16>);

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(BackendPort(Mutex::new(5000)))
        .setup(|app| {
            let app_handle = app.handle().clone();
            let port_state: State<BackendPort> = app.state();

            // Pick a free port (fallback to 5000)
            let port = portpicker::pick_unused_port().unwrap_or(5000);
            *port_state.0.lock().unwrap() = port;

            // In release builds, launch the bundled Python sidecar
            #[cfg(not(debug_assertions))]
            {
                use tauri_plugin_shell::ShellExt;
                let sidecar = app_handle
                    .shell()
                    .sidecar("camellia-backend")
                    .unwrap()
                    .env("PORT", port.to_string())
                    .env("FLASK_ENV", "production")
                    .env("DESKTOP_MODE", "1");

                let (mut rx, _child) = sidecar.spawn().expect("Failed to start backend");

                tauri::async_runtime::spawn(async move {
                    use tauri_plugin_shell::process::CommandEvent;
                    while let Some(event) = rx.recv().await {
                        match event {
                            CommandEvent::Stdout(line) => {
                                let s = String::from_utf8_lossy(&line);
                                println!("[backend] {}", s.trim());
                            }
                            CommandEvent::Stderr(line) => {
                                let s = String::from_utf8_lossy(&line);
                                eprintln!("[backend:err] {}", s.trim());
                            }
                            _ => {}
                        }
                    }
                });
            }

            // Wait for Flask to become ready (max 10 s)
            let check_url = format!("http://127.0.0.1:{}/api/auth/status", port);
            let ready = (0..50).any(|_| {
                std::thread::sleep(std::time::Duration::from_millis(200));
                reqwest::blocking::get(&check_url)
                    .map(|r| r.status().as_u16() < 500)
                    .unwrap_or(false)
            });

            if !ready {
                eprintln!("[tauri] WARNING: backend did not respond in time");
            }

            // Update the window URL to point to the correct port and show it
            if let Some(window) = app_handle.get_webview_window("main") {
                let url = format!("http://127.0.0.1:{}", port);
                // In dev mode the window already points to Next.js dev server;
                // in release it loads the embedded static files served by Flask.
                #[cfg(not(debug_assertions))]
                {
                    let _ = window.navigate(url.parse().unwrap());
                }
                window.show().unwrap();
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_backend_port,
            commands::check_backend_health,
            commands::get_app_version,
            commands::open_docs,
        ])
        .run(tauri::generate_context!())
        .expect("error while running camellia shield");
}

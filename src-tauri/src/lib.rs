mod discovery;
mod opencode;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .manage(opencode::OpenCodeState::default())
        .invoke_handler(tauri::generate_handler![
            discovery::discover_wireshark,
            discovery::discover_mitmproxy,
            opencode::discover_opencode,
            opencode::connect_opencode,
            opencode::disconnect_opencode,
            opencode::opencode_status,
        ])
        .build(tauri::generate_context!())
        .expect("could not build TelemetryRadar desktop")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested {
                code: None, api, ..
            } = event
            {
                api.prevent_exit();
                app.state::<opencode::OpenCodeState>().begin_shutdown();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(error) = app.state::<opencode::OpenCodeState>().shutdown().await {
                        eprintln!("OpenCode shutdown: {error}");
                    }
                    app.exit(0);
                });
            }
        });
}

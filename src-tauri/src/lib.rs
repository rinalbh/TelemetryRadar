mod analysis;
mod capture;
mod discovery;
mod opencode;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .manage(opencode::OpenCodeState::default())
        .manage(capture::CaptureState::default())
        .invoke_handler(tauri::generate_handler![
            discovery::discover_wireshark,
            discovery::discover_mitmproxy,
            opencode::discover_opencode,
            opencode::connect_opencode,
            opencode::disconnect_opencode,
            opencode::opencode_status,
            analysis::analyze_capture,
            analysis::cancel_analysis,
            analysis::respond_opencode_permission,
            analysis::prepare_analysis,
            analysis::discard_analysis_draft,
            analysis::stop_capture_and_analyze,
            analysis::analysis_status,
            capture::start_capture,
            capture::capture_status,
            capture::stop_capture,
            capture::capture_interfaces,
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
                app.state::<capture::CaptureState>().begin_shutdown();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    app.state::<capture::CaptureState>().shutdown().await;
                    if let Err(error) = app.state::<opencode::OpenCodeState>().shutdown().await {
                        eprintln!("OpenCode shutdown: {error}");
                    }
                    app.state::<opencode::OpenCodeState>()
                        .analyses
                        .wait_active()
                        .await;
                    app.exit(0);
                });
            }
        });
}

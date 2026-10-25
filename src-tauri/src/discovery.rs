use serde::Serialize;
use std::path::PathBuf;
use telemetryradar::{mitmproxy, wireshark};

/// Each tool has an independent result so one missing dependency never hides another.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Discovery<T> {
    Available { installation: T },
    Unavailable { message: String },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WiresharkInstallation {
    version: String,
    dumpcap: String,
    tshark: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MitmproxyInstallation {
    version: String,
    mitmdump: String,
}

fn explicit_path(path: Option<String>) -> Option<PathBuf> {
    path.filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn discovery_result<T>(result: telemetryradar::Result<T>) -> Discovery<T> {
    match result {
        Ok(installation) => Discovery::Available { installation },
        Err(error) => Discovery::Unavailable {
            message: error.to_string(),
        },
    }
}

/// Only runs the library's version/help probes. Never enumerates or opens capture devices.
#[tauri::command]
pub async fn discover_wireshark(
    executable_path: Option<String>,
) -> Result<Discovery<WiresharkInstallation>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        discovery_result(
            wireshark::Installation::detect(explicit_path(executable_path)).map(|installation| {
                WiresharkInstallation {
                    version: installation.version,
                    dumpcap: installation.dumpcap.to_string_lossy().into_owned(),
                    tshark: installation.tshark.to_string_lossy().into_owned(),
                }
            }),
        )
    })
    .await
    .map_err(|error| format!("Wireshark discovery task failed: {error}"))
}

/// Only probes mitmdump's version. No local session or certificate API is called.
#[tauri::command]
pub async fn discover_mitmproxy(
    executable_path: Option<String>,
) -> Result<Discovery<MitmproxyInstallation>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        discovery_result(
            mitmproxy::Installation::detect(explicit_path(executable_path)).map(|installation| {
                MitmproxyInstallation {
                    version: installation.version.to_string(),
                    mitmdump: installation.mitmdump.to_string_lossy().into_owned(),
                }
            }),
        )
    })
    .await
    .map_err(|error| format!("mitmproxy discovery task failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn discovery_wire_contract_matches_frontend_discriminants() {
        let available = Discovery::Available {
            installation: WiresharkInstallation {
                version: "5.0.0".into(),
                dumpcap: "C:/Wireshark/dumpcap.exe".into(),
                tshark: "C:/Wireshark/tshark.exe".into(),
            },
        };
        assert_eq!(
            serde_json::to_value(available).unwrap(),
            json!({
                "status": "available",
                "installation": {
                    "version": "5.0.0",
                    "dumpcap": "C:/Wireshark/dumpcap.exe",
                    "tshark": "C:/Wireshark/tshark.exe"
                }
            })
        );
        let unavailable: Discovery<MitmproxyInstallation> = Discovery::Unavailable {
            message: "missing tool".into(),
        };
        assert_eq!(
            serde_json::to_value(unavailable).unwrap(),
            json!({
                "status": "unavailable", "message": "missing tool"
            })
        );
    }
}

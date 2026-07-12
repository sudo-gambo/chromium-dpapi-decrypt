use base64::Engine;
use std::path::PathBuf;
use std::env;
use std::fs;
use crate::browsers::{BrowserInfo};



pub fn get_encrypted_key(browser: &BrowserInfo, manual_path: Option<&str>) -> Result<Vec<u8>, String> {
    let path = if let Some(p) = manual_path {
        PathBuf::from(p)
    } else {
        let local_appdata =
            env::var("LOCALAPPDATA").map_err(|_| "LOCALAPPDATA not set".to_string())?;
        PathBuf::from(local_appdata)
            .join(browser.local_state_dir)
            .join("Local State")
    };

    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {}", path.display(), e))?;

    let json: serde_json::Value =
        serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;

    if let Some(_) = json["os_crypt"]["app_bound_encrypted_key"].as_str() {
        eprintln!("Note: app_bound_encrypted_key found. This tool uses DPAPI, not IElevator.");
    }

    let b64 = json["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or("Key 'os_crypt.encrypted_key' not found in Local State")?;

    base64::engine::general_purpose::STANDARD
        .decode(b64.trim_end())
        .map_err(|e| format!("Base64 decode error: {}", e))
}
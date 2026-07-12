// decrypt_chromium_key.rs – Decrypts Chromium DPAPI‑encrypted master key
// Usage: decrypt_chromium_key.exe chrome
//        decrypt_chromium_key.exe edge
//        decrypt_chromium_key.exe brave
//        decrypt_chromium_key.exe chrome "C:\path\to\Local State"

use std::env;
use std::fs;
use std::path::PathBuf;
use base64::Engine;
use windows::Win32::Security::Cryptography::{
    CryptUnprotectData, CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN,
};
use windows::Win32::Foundation::{LocalFree, HLOCAL};

struct BrowserInfo {
    name: &'static str,
    local_state_dir: &'static str,
}

const BROWSERS: &[BrowserInfo] = &[
    BrowserInfo {
        name: "chrome",
        local_state_dir: "Google\\Chrome\\User Data",
    },
    BrowserInfo {
        name: "edge",
        local_state_dir: "Microsoft\\Edge\\User Data",
    },
    BrowserInfo {
        name: "brave",
        local_state_dir: "BraveSoftware\\Brave-Browser\\User Data",
    },
];

fn get_encrypted_key(browser: &BrowserInfo, manual_path: Option<&str>) -> Result<Vec<u8>, String> {
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

pub fn get_master_key() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <browser> [path/to/Local State]", args[0]);
        return;
    }

    let browser_name = args[1].to_lowercase();
    let info = BROWSERS
        .iter()
        .find(|b| b.name == browser_name)
        .expect("Unknown browser");

    let manual_path = if args.len() == 3 {
        Some(args[2].as_str())
    } else {
        None
    };

    let enc_key = get_encrypted_key(info, manual_path).expect("Failed to get encrypted key");

    if enc_key.len() < 5 || &enc_key[..5] != b"DPAPI" {
        eprintln!("Error: encrypted_key does not start with 'DPAPI' – wrong format."); 
        return;
    }
    let blob = &enc_key[5..];

    let input = CRYPT_INTEGER_BLOB {
        cbData: blob.len() as u32,
        pbData: blob.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    unsafe {
        let result = CryptUnprotectData(
            &input,
            None,
            None,
            Some(std::ptr::null()),    
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        );

        if result.is_err() {
            eprintln!("CryptUnprotectData failed: {:?}", result.err());
            return;
        }

        let key = std::slice::from_raw_parts(output.pbData, output.cbData as usize);

        // The decrypted key is exactly 32 bytes for most Chromium versions.
        // If longer, we take the first 32 bytes (sometimes there's no prefix).
        let master_key = if key.len() >= 32 {
            &key[..32]
        } else {
            eprintln!("Unexpected key length: {}", key.len());
            LocalFree(HLOCAL(output.pbData as *mut std::ffi::c_void));  // fixed
            return;
        };

        println!("{}", base64::engine::general_purpose::STANDARD.encode(master_key));

        LocalFree(HLOCAL(output.pbData as *mut std::ffi::c_void)); // fixed
    }
}
use std::fs;
use std::path::Path;

const MAX_FILE_SIZE: u64 = 200 * 1024 * 1024; // 200 MB
const ALLOWED_EXTENSIONS: &[&str] = &["pcap", "pcapng", "cap"];

#[tauri::command]
fn read_file_bytes(path: String) -> Result<Vec<u8>, String> {
  let file_path = Path::new(&path);

  // Validate file exists
  if !file_path.exists() {
    return Err("File not found".to_string());
  }

  // Canonicalize to resolve symlinks and ../ traversal
  let canonical = file_path.canonicalize()
    .map_err(|e| format!("Invalid path: {}", e))?;

  // Validate extension
  let ext = canonical.extension()
    .and_then(|e| e.to_str())
    .map(|e| e.to_lowercase())
    .unwrap_or_default();

  if !ALLOWED_EXTENSIONS.contains(&ext.as_str()) {
    return Err("File type not allowed. Only .pcap, .pcapng, and .cap files are supported.".to_string());
  }

  // Check file size
  let metadata = fs::metadata(&canonical)
    .map_err(|e| format!("Cannot read file metadata: {}", e))?;

  if metadata.len() > MAX_FILE_SIZE {
    return Err(format!("File too large ({} MB). Maximum is {} MB.",
      metadata.len() / (1024 * 1024),
      MAX_FILE_SIZE / (1024 * 1024)));
  }

  // Read file
  fs::read(&canonical).map_err(|e| format!("Failed to read file: {}", e))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_dialog::init())
    .invoke_handler(tauri::generate_handler![read_file_bytes])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

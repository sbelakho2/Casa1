//! macOS HID game controller monitor.
//!
//! Provides polling-based detection of game controller connections and
//! disconnections on macOS by querying IORegistry for `IOHIDDevice` entries
//! that match known game controller vendor/product IDs.
//!
//! This module implements Phase 5.3.2 of the Casa1 project — Game Controller
//! Hotplug Detection. It follows the same polling pattern used by audio device
//! hotplug in [`RealAudioBackend::detect_device_changes`](super::real_audio::RealAudioBackend::detect_device_changes).

use crate::error::AppResult;
use std::collections::HashMap;
use std::process::Command;

// ── Known game controller vendor IDs ────────────────────────────────────────

/// Microsoft Corporation
const VID_MICROSOFT: u16 = 0x045E;
/// Sony Interactive Entertainment
const VID_SONY: u16 = 0x054C;
/// Nintendo Co., Ltd.
const VID_NINTENDO: u16 = 0x057E;
/// Mad Catz, Inc.
const VID_MADCATZ: u16 = 0x0738;
/// Logitech Inc.
const VID_LOGITECH: u16 = 0x046D;
/// Razer USA Ltd.
const VID_RAZER: u16 = 0x1532;
/// Valve Corporation
const VID_VALVE: u16 = 0x28DE;
/// 8BitDo
const VID_8BITDO: u16 = 0x2DC8;
/// PowerA
const VID_POWERA: u16 = 0x24C6;
/// HORI
const VID_HORI: u16 = 0x0F0D;
/// Thrustmaster
const VID_THRUSTMASTER: u16 = 0x044F;

/// Set of known game controller vendor IDs.
const KNOWN_VIDS: &[u16] = &[
    VID_MICROSOFT,
    VID_SONY,
    VID_NINTENDO,
    VID_MADCATZ,
    VID_LOGITECH,
    VID_RAZER,
    VID_VALVE,
    VID_8BITDO,
    VID_POWERA,
    VID_HORI,
    VID_THRUSTMASTER,
];

/// Vendors whose VID is exclusively used for game controllers; a device from
/// one of these vendors is a controller regardless of its product ID.
const VID_ONLY_CONTROLLER_VENDORS: &[u16] = &[VID_VALVE, VID_8BITDO, VID_POWERA, VID_MADCATZ];

/// Microsoft Xbox controller product IDs that are XInput-capable.
const XINPUT_PIDS: &[(u16, u16)] = &[
    (VID_MICROSOFT, 0x0202), // Xbox Controller
    (VID_MICROSOFT, 0x0285), // Xbox Controller S
    (VID_MICROSOFT, 0x0289), // Xbox Controller S (Japan)
    (VID_MICROSOFT, 0x028E), // Xbox 360 Controller
    (VID_MICROSOFT, 0x02D1), // Xbox One Controller
    (VID_MICROSOFT, 0x02E0), // Xbox One Wireless Controller (model 1708)
    (VID_MICROSOFT, 0x02DD), // Xbox One Controller (Bluetooth)
    (VID_MICROSOFT, 0x02E3), // Xbox One Elite Controller
    (VID_MICROSOFT, 0x02EA), // Xbox One S Controller
    (VID_MICROSOFT, 0x02FD), // Xbox One S Controller (Bluetooth)
    (VID_MICROSOFT, 0x0B00), // Xbox Elite 2 Controller
    (VID_MICROSOFT, 0x0B05), // Xbox Elite 2 Controller (Bluetooth)
    (VID_MICROSOFT, 0x0B12), // Xbox Series X Controller
    (VID_MICROSOFT, 0x0B13), // Xbox Series X Controller (Bluetooth)
    (VID_MICROSOFT, 0x0B20), // Xbox Adaptive Controller
    (VID_MICROSOFT, 0x0B22), // Xbox Series X Controller (Bluetooth LE)
];

// ── Public types ───────────────────────────────────────────────────────────

/// Represents a detected game controller on the macOS host system.
#[derive(Debug, Clone)]
pub struct HostController {
    /// Human-readable product name (e.g., "Xbox Wireless Controller").
    pub name: String,
    /// USB vendor ID from the device descriptor.
    pub vendor_id: u16,
    /// USB product ID from the device descriptor.
    pub product_id: u16,
    /// Unique identifier (serial number, or a path-based fallback).
    pub identifier: String,
    /// Whether this controller appears to be XInput-capable
    /// (i.e., an Xbox or Xbox-compatible controller).
    pub xinput_capable: bool,
}

/// Polling-based monitor for game controller hotplug events.
///
/// Usage:
/// ```ignore
/// let mut monitor = HidMonitor::new();
/// loop {
///     let (added, removed) = monitor.poll_for_changes()?;
///     for ctrl in added { /* connect */ }
///     for ctrl in removed { /* disconnect */ }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct HidMonitor {
    /// Previously detected controllers, keyed by their unique identifier.
    previous: HashMap<String, HostController>,
    /// Whether the first scan has completed.
    initialized: bool,
    /// Cached scan results so `poll_for_changes` does not spawn a fresh
    /// `ioreg` process per call (the consumer polls every frame).
    cached_scan: Option<(std::time::Instant, Vec<HostController>)>,
}

impl HidMonitor {
    /// Creates a new `HidMonitor` with no previous state.
    ///
    /// The initial scan happens on the first call to [`poll_for_changes`](#method.poll_for_changes).
    pub fn new() -> Self {
        Self {
            previous: HashMap::new(),
            initialized: false,
            cached_scan: None,
        }
    }

    /// Polls the system for game controller changes since the last call.
    ///
    /// Returns `(added, removed)` tuples containing the controllers that have
    /// been connected or disconnected respectively.
    ///
    /// On the first call, all currently connected controllers are returned as
    /// "added" so the caller can bootstrap the initial state.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying system command (`ioreg`) cannot be
    /// executed. Returns an empty list (no controllers) if `ioreg` is not
    /// available on the system.
    pub fn poll_for_changes(&mut self) -> AppResult<(Vec<HostController>, Vec<HostController>)> {
        const SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
        let current = match &self.cached_scan {
            Some((scanned_at, cached)) if scanned_at.elapsed() < SCAN_INTERVAL => cached.clone(),
            _ => {
                let fresh = scan_controllers()?;
                self.cached_scan = Some((std::time::Instant::now(), fresh.clone()));
                fresh
            }
        };

        if !self.initialized {
            // First scan: return everything as "added" for bootstrapping.
            self.previous = current
                .iter()
                .map(|c| (c.identifier.clone(), c.clone()))
                .collect();
            self.initialized = true;
            return Ok((current, Vec::new()));
        }

        let mut added = Vec::new();
        let mut removed = Vec::new();

        // Find newly connected controllers.
        for controller in &current {
            if !self.previous.contains_key(&controller.identifier) {
                added.push(controller.clone());
            }
        }

        // Find recently disconnected controllers.
        for (id, controller) in &self.previous {
            if !current.iter().any(|c| c.identifier == *id) {
                removed.push(controller.clone());
            }
        }

        // Update previous state.
        self.previous = current
            .into_iter()
            .map(|c| (c.identifier.clone(), c))
            .collect();

        Ok((added, removed))
    }
}

impl Default for HidMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Controller scanning ────────────────────────────────────────────────────

/// Scans the system for connected game controllers via `ioreg`.
///
/// Uses `ioreg -r -c IOHIDDevice` to enumerate all HID devices and filters
/// for entries with known game controller vendor IDs or product names
/// containing keywords like "gamepad", "controller", or "joystick".
///
/// Returns an empty vector if `ioreg` is unavailable or fails gracefully
/// (matching the documented contract of [`HidMonitor::poll_for_changes`]).
fn scan_controllers() -> AppResult<Vec<HostController>> {
    let output = match Command::new("ioreg")
        .args(["-r", "-c", "IOHIDDevice"])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("[real_hid] ioreg unavailable, reporting no controllers: {e}");
            return Ok(Vec::new());
        }
    };

    if !output.status.success() {
        // ioreg may not be available; return empty list gracefully.
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ioreg_devices(&text))
}

/// Parse `ioreg -r -c IOHIDDevice` output into a list of detected controllers.
///
/// The output format is a tree of IORegistry entries. Each IOHIDDevice entry
/// is enclosed in `{ ... }` and contains key-value pairs:
///
/// ```text
/// +-o IOHIDDevice  <class IOHIDDevice, ...>
///   {
///     "Product" = "Xbox Wireless Controller"
///     "VendorID" = 1118
///     "ProductID" = 736
///     "SerialNumber" = "ABC123"
///     "Transport" = "USB"
///   }
/// ```
fn parse_ioreg_devices(text: &str) -> Vec<HostController> {
    let mut controllers = Vec::new();

    // State machine: tracks whether we are inside an IOHIDDevice `{ }` block.
    let mut in_device = false;
    let mut brace_depth = 0i32;
    let mut product = String::new();
    let mut vendor_id = 0u16;
    let mut product_id = 0u16;
    let mut serial = String::new();
    let mut entry_id = String::new();

    for line in text.lines() {
        let trimmed = line.trim();

        if !in_device {
            // Look for the start of an IOHIDDevice entry.
            if trimmed.starts_with("+-o") && trimmed.contains("IOHIDDevice") {
                in_device = true;
                brace_depth = 0;
                product.clear();
                vendor_id = 0;
                product_id = 0;
                serial.clear();
                entry_id = parse_ioreg_entry_id(trimmed);
            }
            continue;
        }

        // Track brace depth to handle nested `{ }`.
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth -= 1,
                _ => {}
            }
        }

        if brace_depth < 0 {
            // End of device block (shouldn't happen, but be safe).
            in_device = false;
            continue;
        }

        if brace_depth == 0 {
            // End of device block (closing brace brought depth to 0).
            if is_game_controller(vendor_id, product_id, &product) {
                controllers.push(build_controller(
                    &product,
                    vendor_id,
                    product_id,
                    &serial,
                    &entry_id,
                    controllers.len(),
                ));
            }
            in_device = false;
            continue;
        }

        // Parse key = value pairs inside the block.
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim().trim_matches('"').to_string();
            let raw_val = trimmed[eq_pos + 1..].trim();
            let val = raw_val.trim_matches('"');

            match key.as_str() {
                "Product" | "USB Product Name" => {
                    product = val.to_string();
                }
                "VendorID" | "idVendor" => {
                    vendor_id = val.parse().unwrap_or(0);
                }
                "ProductID" | "idProduct" => {
                    product_id = val.parse().unwrap_or(0);
                }
                "SerialNumber" | "USB Serial Number" | "Serial Number" if !val.is_empty() => {
                    serial = val.to_string();
                }
                _ => {}
            }
        }
    }

    controllers
}

/// Extract the IORegistry entry id (the `id 0x…` token on the `+-o` line),
/// which is a stable per-device identifier across rescans.
fn parse_ioreg_entry_id(line: &str) -> String {
    let mut words = line.split_whitespace();
    while let Some(word) = words.next() {
        if word == "id"
            && let Some(value) = words.next()
        {
            return value.trim_matches(',').to_string();
        }
    }
    String::new()
}

/// Returns `true` if the device with the given VID/PID/name appears to be a
/// game controller.
fn is_game_controller(vendor_id: u16, product_id: u16, product: &str) -> bool {
    let lower = product.to_ascii_lowercase();
    let name_is_controller =
        lower.contains("gamepad") || lower.contains("controller") || lower.contains("joystick");

    // Strictly-gaming vendors match on VID alone.
    if VID_ONLY_CONTROLLER_VENDORS.contains(&vendor_id) {
        return true;
    }

    // Known vendors (Microsoft, Sony, Nintendo, Logitech, Razer, HORI,
    // Thrustmaster) also cover keyboards, mice, and webcams, so a VID match
    // alone would report phantom gamepads.  Require an XInput-capable
    // product ID (Xbox controllers) or a controller-like product name.
    if KNOWN_VIDS.contains(&vendor_id) {
        return is_xinput_capable(vendor_id, product_id) || name_is_controller;
    }

    // Unknown vendor: fall back to the product name keywords.
    name_is_controller
}

/// Returns `true` if the device with the given VID/PID is XInput-capable.
fn is_xinput_capable(vendor_id: u16, product_id: u16) -> bool {
    XINPUT_PIDS.contains(&(vendor_id, product_id))
}

/// Build a `HostController` from parsed fields.
fn build_controller(
    name: &str,
    vendor_id: u16,
    product_id: u16,
    serial: &str,
    entry_id: &str,
    index: usize,
) -> HostController {
    // Prefer the serial number, then the stable IORegistry entry id; the
    // enumeration index is only a last resort and is not stable across
    // scans (unplugging one of two identical controllers would otherwise
    // rename the survivor and churn remove+add events).
    let identifier = if !serial.is_empty() {
        format!("{:04x}:{:04x}:{}", vendor_id, product_id, serial)
    } else if !entry_id.is_empty() {
        format!("{:04x}:{:04x}:{}", vendor_id, product_id, entry_id)
    } else {
        format!("{:04x}:{:04x}:hid{}", vendor_id, product_id, index)
    };

    HostController {
        name: if name.is_empty() {
            format!("Game Controller ({:04x}:{:04x})", vendor_id, product_id)
        } else {
            name.to_string()
        },
        vendor_id,
        product_id,
        identifier,
        xinput_capable: is_xinput_capable(vendor_id, product_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_xbox_controller() {
        let sample = r#"
+-o IOHIDDevice  <class IOHIDDevice, id 0x12345678, registered, matched, active, busy 0, retain count 7>
{
  "Product" = "Xbox Wireless Controller"
  "VendorID" = 1118
  "ProductID" = 736
  "SerialNumber" = "ABC123"
  "Transport" = "USB"
}
"#;
        let devices = parse_ioreg_devices(sample);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "Xbox Wireless Controller");
        assert_eq!(devices[0].vendor_id, 1118);
        assert_eq!(devices[0].product_id, 736);
        assert!(devices[0].xinput_capable);
    }

    #[test]
    fn test_parse_sony_controller() {
        let sample = r#"
+-o IOHIDDevice  <class IOHIDDevice, id 0x87654321, registered, matched, active, busy 0, retain count 5>
{
  "Product" = "DualSense Wireless Controller"
  "VendorID" = 1356
  "ProductID" = 3302
  "Transport" = "USB"
}
"#;
        let devices = parse_ioreg_devices(sample);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].name, "DualSense Wireless Controller");
        // Sony VID = 0x054C = 1356
        assert_eq!(devices[0].vendor_id, 1356);
        assert_eq!(devices[0].product_id, 3302);
        assert!(!devices[0].xinput_capable);
    }

    #[test]
    fn test_empty_output() {
        let devices = parse_ioreg_devices("");
        assert!(devices.is_empty());
    }

    #[test]
    fn test_non_controller_hid_device_is_filtered() {
        let sample = r#"
+-o IOHIDDevice  <class IOHIDDevice, id 0x11111111, registered, matched, active, busy 0, retain count 3>
{
  "Product" = "Apple Keyboard"
  "VendorID" = 1452
  "ProductID" = 579
  "Transport" = "USB"
}
"#;
        let devices = parse_ioreg_devices(sample);
        assert!(devices.is_empty());
    }

    #[test]
    fn test_hid_monitor_initial_scan_returns_all() {
        let mut monitor = HidMonitor::new();
        // Before first scan, poll_for_changes returns all current controllers.
        let (_added, removed) = monitor.poll_for_changes().unwrap();
        // Added may be empty if no controllers are connected, which is fine.
        assert!(removed.is_empty());
        assert!(monitor.initialized);
    }

    #[test]
    fn test_xinput_capable_detection() {
        // Xbox Series X controller (Bluetooth)
        assert!(is_xinput_capable(VID_MICROSOFT, 0x0B13));
        // Xbox 360 controller
        assert!(is_xinput_capable(VID_MICROSOFT, 0x028E));
        // Sony DualSense is NOT XInput capable
        assert!(!is_xinput_capable(VID_SONY, 0x0CE6));
    }

    #[test]
    fn test_is_game_controller_known_vid() {
        // XInput-capable product ID matches even without a name keyword.
        assert!(is_game_controller(
            VID_MICROSOFT,
            0x028E,
            "Xbox 360 Controller"
        ));
        // Known vendor + controller-like name.
        assert!(is_game_controller(
            VID_SONY,
            0x0CE6,
            "DualSense Wireless Controller"
        ));
        assert!(is_game_controller(
            VID_NINTENDO,
            0x2006,
            "Switch Pro Controller"
        ));
        // Strictly-gaming vendors match on VID alone.
        assert!(is_game_controller(VID_VALVE, 0x0001, "Steam Controller"));
        assert!(is_game_controller(VID_8BITDO, 0x1234, "8BitDo Device"));
        assert!(is_game_controller(VID_POWERA, 0x0000, "PowerA Device"));
        assert!(is_game_controller(VID_MADCATZ, 0x0000, "Mad Catz Device"));
    }

    #[test]
    fn test_known_vendor_non_controller_is_filtered() {
        // Microsoft and Logitech VIDs also cover keyboards/mice/webcams:
        // a VID match alone must not report a phantom gamepad.
        assert!(!is_game_controller(
            VID_MICROSOFT,
            0x0001,
            "Microsoft Ergonomic Keyboard"
        ));
        assert!(!is_game_controller(
            VID_LOGITECH,
            0xC077,
            "Logitech USB Optical Mouse"
        ));
        assert!(!is_game_controller(VID_SONY, 0x0300, "Sony Device"));
        // XInput-capable product IDs still classify regardless of name.
        assert!(is_game_controller(
            VID_MICROSOFT,
            0x028E,
            "Wireless Receiver"
        ));
    }

    #[test]
    fn test_is_game_controller_by_name() {
        // Unknown VID but name contains keyword.
        assert!(is_game_controller(0x1234, 0x5678, "Generic Gamepad"));
        assert!(is_game_controller(0x1234, 0x5678, "USB Joystick"));
        // Non-controller name
        assert!(!is_game_controller(0x1234, 0x5678, "USB Keyboard"));
    }

    #[test]
    fn test_serial_less_controller_uses_stable_entry_id() {
        let sample = r#"
+-o IOHIDDevice  <class IOHIDDevice, id 0x12345678, registered, matched, active, busy 0, retain count 7>
{
  "Product" = "Xbox Wireless Controller"
  "VendorID" = 1118
  "ProductID" = 736
  "Transport" = "USB"
}
+-o IOHIDDevice  <class IOHIDDevice, id 0x87654321, registered, matched, active, busy 0, retain count 5>
{
  "Product" = "Xbox Wireless Controller"
  "VendorID" = 1118
  "ProductID" = 736
  "Transport" = "USB"
}
"#;
        let devices = parse_ioreg_devices(sample);
        assert_eq!(devices.len(), 2);
        // Identifiers embed the registry entry id, not the enumeration index.
        assert_eq!(devices[0].identifier, "045e:02e0:0x12345678");
        assert_eq!(devices[1].identifier, "045e:02e0:0x87654321");
        assert_ne!(devices[0].identifier, devices[1].identifier);
    }
}

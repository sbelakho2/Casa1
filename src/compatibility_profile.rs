//! Compatibility profiles: the user-mode feature profile a target binary runs
//! under.
//!
//! A profile names the Windows version, the guest architecture, and the
//! optional subsystems the target needs.  The profile-sensitive completeness
//! gate (api_database) uses `optional_features` to decide which
//! `SupportPolicy::OptionalFeature` APIs may pass without a full
//! implementation: an optional feature that the profile explicitly excludes
//! is not part of that target's compatibility surface.

use crate::api_database::WindowsVersion;
use crate::cpu::GuestArch;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// The user-mode feature profile a target binary runs under.
///
/// The `graphics` / `web` / `managed` / `media` booleans describe the main
/// optional subsystems; `optional_features` names the additional optional
/// subsystems this profile EXPLICITLY EXCLUDES (so their
/// `SupportPolicy::OptionalFeature` APIs pass the profile-sensitive
/// completeness gate).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityProfile {
    /// Windows version the target expects.
    pub windows_version: WindowsVersion,
    /// Guest architecture of the target.
    pub guest_arch: GuestArch,
    /// The target uses the graphics subsystem (D3D/DXGI/GDI+).
    pub graphics: bool,
    /// The target uses web subsystem APIs (WinHTTP/WinINet/WebView2).
    pub web: bool,
    /// The target is a managed (.NET/CLR) workload.
    pub managed: bool,
    /// The target uses media subsystem APIs (Media Foundation, audio/video).
    pub media: bool,
    /// Optional subsystems the profile explicitly excludes.
    pub optional_features: BTreeSet<String>,
}

impl CompatibilityProfile {
    /// A native Windows 11 desktop profile: everything enabled, nothing
    /// excluded.  The strictest user-mode profile.
    pub fn win11_native_desktop() -> Self {
        Self {
            windows_version: WindowsVersion::Win11,
            guest_arch: GuestArch::X64,
            graphics: true,
            web: true,
            managed: false,
            media: true,
            optional_features: BTreeSet::new(),
        }
    }

    /// A Windows 11 gaming profile: graphics required, web/media/managed
    /// subsystems excluded.
    pub fn win11_gaming() -> Self {
        Self {
            windows_version: WindowsVersion::Win11,
            guest_arch: GuestArch::X64,
            graphics: true,
            web: false,
            managed: false,
            media: false,
            optional_features: BTreeSet::from([
                "web".to_string(),
                "managed".to_string(),
                "media".to_string(),
            ]),
        }
    }

    /// A legacy Windows 10 x86 desktop profile: graphics required, web and
    /// media excluded (an offline desktop workload).
    pub fn win10_legacy_desktop() -> Self {
        Self {
            windows_version: WindowsVersion::Win10,
            guest_arch: GuestArch::X86,
            graphics: true,
            web: false,
            managed: false,
            media: true,
            optional_features: BTreeSet::from(["web".to_string(), "managed".to_string()]),
        }
    }

    /// A managed (.NET) desktop profile: managed runtime required, native
    /// graphics/web/media subsystems excluded.
    pub fn managed_desktop() -> Self {
        Self {
            windows_version: WindowsVersion::Win11,
            guest_arch: GuestArch::X64,
            graphics: false,
            web: false,
            managed: true,
            media: false,
            optional_features: BTreeSet::from([
                "graphics".to_string(),
                "web".to_string(),
                "media".to_string(),
            ]),
        }
    }

    /// Whether the profile excludes the named optional subsystem.
    pub fn excludes(&self, feature: &str) -> bool {
        self.optional_features.contains(feature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_are_internally_consistent() {
        let desktop = CompatibilityProfile::win11_native_desktop();
        assert_eq!(desktop.windows_version, WindowsVersion::Win11);
        assert_eq!(desktop.guest_arch, GuestArch::X64);
        assert!(desktop.graphics && desktop.web && desktop.media);
        assert!(!desktop.excludes("graphics"));

        let gaming = CompatibilityProfile::win11_gaming();
        assert!(gaming.excludes("web"));
        assert!(gaming.excludes("media"));
        assert!(!gaming.excludes("graphics"));

        let legacy = CompatibilityProfile::win10_legacy_desktop();
        assert_eq!(legacy.windows_version, WindowsVersion::Win10);
        assert_eq!(legacy.guest_arch, GuestArch::X86);
        assert!(legacy.excludes("web"));

        let managed = CompatibilityProfile::managed_desktop();
        assert!(managed.managed);
        assert!(managed.excludes("graphics"));
        assert!(managed.excludes("web"));
    }
}

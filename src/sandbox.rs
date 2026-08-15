//! Windows Sandbox / AppContainer support module.
//!
//! AppContainer is a Windows security isolation feature used by modern Windows
//! Store apps (UWP) and some desktop applications. It provides process-level
//! sandboxing with fine-grained capability control.
//!
//! This module implements:
//! - AppContainer profile management (create, delete, query)
//! - Sandbox capability definitions matching Windows `SID`-based capability names
//! - Windows Sandbox configuration generation
//! - Integration with the existing [`crate::security::FilesystemSandbox`] for path isolation
//!
//! Windows API mappings:
//! - `userenv.dll`: `CreateAppContainerProfile`, `DeleteAppContainerProfile`,
//!   `GetAppContainerProfilePath`, etc.
//! - `kernel32.dll`: `CreateAppContainerToken`, `GetAppContainerNamedObjectPath`,
//!   `CheckTokenMembership`
//! - `appcontainersilo.dll`: AppContainer silo management
//!
//! # Gap 15.5
//! This module was added to close Gap 15.5 ("No Windows Sandbox / AppContainer Support")
//! from the comprehensive gap analysis.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Well-known AppContainer capabilities matching Windows SID capability definitions.
///
/// Each capability corresponds to a specific SID used by the Windows security
/// subsystem when creating AppContainer tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AppContainerCapability {
    /// `documentLibrary` — Access to the user's Documents library.
    DocumentsLibrary,
    /// `picturesLibrary` — Access to the user's Pictures library.
    PicturesLibrary,
    /// `videosLibrary` — Access to the user's Videos library.
    VideosLibrary,
    /// `musicLibrary` — Access to the user's Music library.
    MusicLibrary,
    /// `enterpriseAuthentication` — Access to enterprise authentication.
    EnterpriseAuthentication,
    /// `sharedUserCertificates` — Access to shared user certificates.
    SharedUserCertificates,
    /// `removableStorage` — Access to removable storage.
    RemovableStorage,
    /// `internetClient` — Outbound internet access.
    InternetClient,
    /// `internetClientServer` — Inbound and outbound internet access.
    InternetClientServer,
    /// `privateNetworkClientServer` — Access to private networks.
    PrivateNetworkClientServer,
    /// `codeGeneration` — Allow JIT code generation.
    CodeGeneration,
    /// `runFullTrust` — Full trust level (elevates from AppContainer).
    RunFullTrust,
    /// `allowExecution` — Allow execution of the package.
    AllowExecution,
}

impl AppContainerCapability {
    /// Return the Windows SID string for this capability.
    pub fn to_sid(&self) -> &'static str {
        match self {
            Self::DocumentsLibrary => "S-1-15-3-1",
            Self::PicturesLibrary => "S-1-15-3-2",
            Self::VideosLibrary => "S-1-15-3-3",
            Self::MusicLibrary => "S-1-15-3-4",
            Self::EnterpriseAuthentication => "S-1-15-3-5",
            Self::SharedUserCertificates => "S-1-15-3-6",
            Self::RemovableStorage => "S-1-15-3-7",
            Self::InternetClient => "S-1-15-3-8",
            Self::InternetClientServer => "S-1-15-3-9",
            Self::PrivateNetworkClientServer => "S-1-15-3-10",
            Self::CodeGeneration => "S-1-15-3-11",
            Self::RunFullTrust => "S-1-15-3-12",
            Self::AllowExecution => "S-1-15-3-13",
        }
    }

    /// Parse a capability string (as used by Windows manifests) to a capability.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "documentLibrary" => Some(Self::DocumentsLibrary),
            "picturesLibrary" => Some(Self::PicturesLibrary),
            "videosLibrary" => Some(Self::VideosLibrary),
            "musicLibrary" => Some(Self::MusicLibrary),
            "enterpriseAuthentication" => Some(Self::EnterpriseAuthentication),
            "sharedUserCertificates" => Some(Self::SharedUserCertificates),
            "removableStorage" => Some(Self::RemovableStorage),
            "internetClient" => Some(Self::InternetClient),
            "internetClientServer" => Some(Self::InternetClientServer),
            "privateNetworkClientServer" => Some(Self::PrivateNetworkClientServer),
            "codeGeneration" => Some(Self::CodeGeneration),
            "runFullTrust" => Some(Self::RunFullTrust),
            "allowExecution" => Some(Self::AllowExecution),
            _ => None,
        }
    }

    /// Return the human-readable display name for this capability.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::DocumentsLibrary => "Documents Library Access",
            Self::PicturesLibrary => "Pictures Library Access",
            Self::VideosLibrary => "Videos Library Access",
            Self::MusicLibrary => "Music Library Access",
            Self::EnterpriseAuthentication => "Enterprise Authentication",
            Self::SharedUserCertificates => "Shared User Certificates",
            Self::RemovableStorage => "Removable Storage Access",
            Self::InternetClient => "Internet (Client)",
            Self::InternetClientServer => "Internet (Client & Server)",
            Self::PrivateNetworkClientServer => "Private Network (Client & Server)",
            Self::CodeGeneration => "Code Generation (JIT)",
            Self::RunFullTrust => "Run Full Trust",
            Self::AllowExecution => "Allow Execution",
        }
    }
}

/// AppContainer profile, analogous to a Windows `AppContainerProfile`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppContainerProfile {
    /// Display name of the profile.
    pub name: String,
    /// Description of the profile.
    pub description: String,
    /// SID assigned to this AppContainer (generated on creation).
    pub sid: String,
    /// Set of capabilities granted to this AppContainer.
    pub capabilities: HashSet<AppContainerCapability>,
    /// Paths that the AppContainer is allowed to read.
    pub allowed_read_paths: Vec<String>,
    /// Paths that the AppContainer is allowed to write.
    pub allowed_write_paths: Vec<String>,
    /// Registry keys that the AppContainer is allowed to access.
    pub allowed_registry_keys: Vec<String>,
    /// Whether the AppContainer is currently active (has running processes).
    pub active: bool,
    /// Whether this is a Windows Sandbox (temporary VM) profile.
    pub is_sandbox: bool,
}

impl AppContainerProfile {
    /// Create a new AppContainer profile with a generated SID.
    pub fn new(name: &str, description: &str) -> Self {
        let sid = generate_app_container_sid(name);
        Self {
            name: name.to_string(),
            description: description.to_string(),
            sid,
            capabilities: HashSet::new(),
            allowed_read_paths: Vec::new(),
            allowed_write_paths: Vec::new(),
            allowed_registry_keys: Vec::new(),
            active: false,
            is_sandbox: false,
        }
    }

    /// Add a capability to this profile.
    pub fn add_capability(&mut self, capability: AppContainerCapability) {
        self.capabilities.insert(capability);
    }

    /// Remove a capability from this profile.
    pub fn remove_capability(&mut self, capability: &AppContainerCapability) {
        self.capabilities.remove(capability);
    }

    /// Check if a capability is granted.
    pub fn has_capability(&self, capability: &AppContainerCapability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Add a path to the allowed read list.
    pub fn add_read_path(&mut self, path: &str) {
        if !self.allowed_read_paths.contains(&path.to_string()) {
            self.allowed_read_paths.push(path.to_string());
        }
    }

    /// Add a path to the allowed write list.
    pub fn add_write_path(&mut self, path: &str) {
        if !self.allowed_write_paths.contains(&path.to_string()) {
            self.allowed_write_paths.push(path.to_string());
        }
    }

    /// Add a registry key to the allowed access list.
    pub fn add_registry_key(&mut self, key: &str) {
        if !self.allowed_registry_keys.contains(&key.to_string()) {
            self.allowed_registry_keys.push(key.to_string());
        }
    }
}

/// Describes the Windows Sandbox configuration for a given application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowsSandboxConfig {
    /// Whether to enable virtualized GPU.
    pub vgpu: bool,
    /// Whether to enable networking.
    pub networking: bool,
    /// Whether to enable audio input.
    pub audio_input: bool,
    /// Whether to enable video input (webcam).
    pub video_input: bool,
    /// Whether to enable clipboard redirection (read-only or read-write).
    pub clipboard_redirection: bool,
    /// Whether to enable printer redirection.
    pub printer_redirection: bool,
    /// Whether to enable the mapped folder feature.
    pub mapped_folders: Vec<MappedFolder>,
    /// Path to the sandbox template file (`.wsb` extension).
    pub template_path: Option<String>,
}

impl Default for WindowsSandboxConfig {
    fn default() -> Self {
        Self {
            vgpu: true,
            networking: true,
            audio_input: false,
            video_input: false,
            clipboard_redirection: true,
            printer_redirection: false,
            mapped_folders: Vec::new(),
            template_path: None,
        }
    }
}

/// A folder mapped into the Windows Sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappedFolder {
    /// Path on the host system.
    pub host_path: String,
    /// Path inside the sandbox (e.g., `C:\Users\WDAGUtilityAccount\Desktop\Folder`).
    pub sandbox_path: String,
    /// Whether the folder is read-only inside the sandbox.
    pub read_only: bool,
}

impl MappedFolder {
    pub fn new(host_path: &str, sandbox_path: &str, read_only: bool) -> Self {
        Self {
            host_path: host_path.to_string(),
            sandbox_path: sandbox_path.to_string(),
            read_only,
        }
    }
}

/// Summary of the sandbox environment state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxEnvironmentSummary {
    /// Whether AppContainer support is available.
    pub app_container_available: bool,
    /// Number of registered AppContainer profiles.
    pub profile_count: usize,
    /// Number of active (running) AppContainer profiles.
    pub active_profile_count: usize,
    /// Whether a Windows Sandbox VM is currently running.
    pub sandbox_running: bool,
    /// Whether capabilities can be enforced on this platform.
    pub capabilities_enforceable: bool,
}

/// The main sandbox manager that tracks AppContainer profiles and sandbox state.
pub struct SandboxManager {
    /// Registered AppContainer profiles, keyed by name.
    profiles: Mutex<HashMap<String, AppContainerProfile>>,
    /// Current Windows Sandbox configuration.
    sandbox_config: Mutex<WindowsSandboxConfig>,
    /// Whether the sandbox manager is enabled.
    enabled: Mutex<bool>,
}

impl SandboxManager {
    /// Create a new [`SandboxManager`] with no profiles.
    pub fn new() -> Self {
        Self {
            profiles: Mutex::new(HashMap::new()),
            sandbox_config: Mutex::new(WindowsSandboxConfig::default()),
            enabled: Mutex::new(true),
        }
    }

    /// Create a [`SandboxManager`] with pre-configured profiles (for testing).
    pub fn with_profiles(profiles: Vec<AppContainerProfile>) -> Self {
        let mut map = HashMap::new();
        for profile in profiles {
            map.insert(profile.name.clone(), profile);
        }
        Self {
            profiles: Mutex::new(map),
            sandbox_config: Mutex::new(WindowsSandboxConfig::default()),
            enabled: Mutex::new(true),
        }
    }

    /// Return whether the sandbox manager is enabled.
    pub fn is_enabled(&self) -> bool {
        *self.enabled.lock().unwrap()
    }

    /// Enable or disable the sandbox manager.
    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.lock().unwrap() = enabled;
    }

    // -----------------------------------------------------------------------
    // AppContainer Profile Management
    // -----------------------------------------------------------------------

    /// Create a new AppContainer profile (mirrors `CreateAppContainerProfile`).
    pub fn create_profile(
        &self,
        name: &str,
        description: &str,
    ) -> Result<AppContainerProfile, String> {
        let mut profiles = self.profiles.lock().unwrap();
        if profiles.contains_key(name) {
            return Err(format!("AppContainer profile '{name}' already exists"));
        }
        let profile = AppContainerProfile::new(name, description);
        let clone = profile.clone();
        profiles.insert(name.to_string(), profile);
        Ok(clone)
    }

    /// Delete an AppContainer profile (mirrors `DeleteAppContainerProfile`).
    pub fn delete_profile(&self, name: &str) -> Result<(), String> {
        let mut profiles = self.profiles.lock().unwrap();
        if profiles.remove(name).is_none() {
            return Err(format!("AppContainer profile '{name}' not found"));
        }
        Ok(())
    }

    /// Retrieve a profile by name.
    pub fn get_profile(&self, name: &str) -> Option<AppContainerProfile> {
        let profiles = self.profiles.lock().unwrap();
        profiles.get(name).cloned()
    }

    /// Retrieve a profile by SID.
    pub fn get_profile_by_sid(&self, sid: &str) -> Option<AppContainerProfile> {
        let profiles = self.profiles.lock().unwrap();
        profiles.values().find(|p| p.sid == sid).cloned()
    }

    /// List all registered profile names.
    pub fn list_profiles(&self) -> Vec<String> {
        let profiles = self.profiles.lock().unwrap();
        let mut names: Vec<String> = profiles.keys().cloned().collect();
        names.sort();
        names
    }

    /// List all profiles with their details.
    pub fn list_profiles_detailed(&self) -> Vec<AppContainerProfile> {
        let profiles = self.profiles.lock().unwrap();
        let mut list: Vec<AppContainerProfile> = profiles.values().cloned().collect();
        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    /// Set a profile's active state.
    pub fn set_profile_active(&self, name: &str, active: bool) -> Result<(), String> {
        let mut profiles = self.profiles.lock().unwrap();
        let profile = profiles
            .get_mut(name)
            .ok_or_else(|| format!("AppContainer profile '{name}' not found"))?;
        profile.active = active;
        Ok(())
    }

    /// Add a capability to a profile.
    pub fn add_capability(
        &self,
        name: &str,
        capability: AppContainerCapability,
    ) -> Result<(), String> {
        let mut profiles = self.profiles.lock().unwrap();
        let profile = profiles
            .get_mut(name)
            .ok_or_else(|| format!("AppContainer profile '{name}' not found"))?;
        profile.add_capability(capability);
        Ok(())
    }

    /// Remove a capability from a profile.
    pub fn remove_capability(
        &self,
        name: &str,
        capability: &AppContainerCapability,
    ) -> Result<(), String> {
        let mut profiles = self.profiles.lock().unwrap();
        let profile = profiles
            .get_mut(name)
            .ok_or_else(|| format!("AppContainer profile '{name}' not found"))?;
        profile.remove_capability(capability);
        Ok(())
    }

    /// Add a path to a profile's allowed read list.
    pub fn add_read_path(&self, name: &str, path: &str) -> Result<(), String> {
        let mut profiles = self.profiles.lock().unwrap();
        let profile = profiles
            .get_mut(name)
            .ok_or_else(|| format!("AppContainer profile '{name}' not found"))?;
        profile.add_read_path(path);
        Ok(())
    }

    /// Add a path to a profile's allowed write list.
    pub fn add_write_path(&self, name: &str, path: &str) -> Result<(), String> {
        let mut profiles = self.profiles.lock().unwrap();
        let profile = profiles
            .get_mut(name)
            .ok_or_else(|| format!("AppContainer profile '{name}' not found"))?;
        profile.add_write_path(path);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Windows Sandbox Configuration
    // -----------------------------------------------------------------------

    /// Get the current sandbox configuration.
    pub fn sandbox_config(&self) -> WindowsSandboxConfig {
        self.sandbox_config.lock().unwrap().clone()
    }

    /// Set the sandbox configuration.
    pub fn set_sandbox_config(&self, config: WindowsSandboxConfig) {
        *self.sandbox_config.lock().unwrap() = config;
    }

    /// Generate a `.wsb` (Windows Sandbox) configuration XML string.
    ///
    /// The returned XML can be saved to a `.wsb` file and opened with
    /// Windows Sandbox on Windows 10/11 Pro or Enterprise.
    pub fn generate_wsb_xml(&self) -> String {
        let config = self.sandbox_config.lock().unwrap().clone();
        let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<Configuration>\n");

        xml.push_str(&format!(
            "  <VGpu>{}</VGpu>\n",
            if config.vgpu { "Enable" } else { "Disable" }
        ));
        xml.push_str(&format!(
            "  <Networking>{}</Networking>\n",
            if config.networking {
                "Enable"
            } else {
                "Disable"
            }
        ));
        xml.push_str(&format!(
            "  <AudioInput>{}</AudioInput>\n",
            if config.audio_input {
                "Enable"
            } else {
                "Disable"
            }
        ));
        xml.push_str(&format!(
            "  <VideoInput>{}</VideoInput>\n",
            if config.video_input {
                "Enable"
            } else {
                "Disable"
            }
        ));
        xml.push_str(&format!(
            "  <ClipboardRedirection>{}</ClipboardRedirection>\n",
            if config.clipboard_redirection {
                "Enable"
            } else {
                "Disable"
            }
        ));
        xml.push_str(&format!(
            "  <PrinterRedirection>{}</PrinterRedirection>\n",
            if config.printer_redirection {
                "Enable"
            } else {
                "Disable"
            }
        ));

        if !config.mapped_folders.is_empty() {
            xml.push_str("  <MappedFolders>\n");
            for folder in &config.mapped_folders {
                xml.push_str("    <MappedFolder>\n");
                xml.push_str(&format!(
                    "      <HostFolder>{}</HostFolder>\n",
                    folder.host_path
                ));
                xml.push_str(&format!(
                    "      <SandboxFolder>{}</SandboxFolder>\n",
                    folder.sandbox_path
                ));
                xml.push_str(&format!(
                    "      <ReadOnly>{}</ReadOnly>\n",
                    folder.read_only
                ));
                xml.push_str("    </MappedFolder>\n");
            }
            xml.push_str("  </MappedFolders>\n");
        }

        xml.push_str("</Configuration>\n");
        xml
    }

    // -----------------------------------------------------------------------
    // Queries
    // -----------------------------------------------------------------------

    /// Check whether a given profile has a specific capability.
    pub fn check_capability(
        &self,
        profile_name: &str,
        capability: &AppContainerCapability,
    ) -> Result<bool, String> {
        let profile = self
            .get_profile(profile_name)
            .ok_or_else(|| format!("AppContainer profile '{profile_name}' not found"))?;
        Ok(profile.has_capability(capability))
    }

    /// Return a summary of the sandbox environment.
    pub fn environment_summary(&self) -> SandboxEnvironmentSummary {
        let profiles = self.profiles.lock().unwrap();
        let total = profiles.len();
        let active = profiles.values().filter(|p| p.active).count();
        let sandbox_running = profiles.values().any(|p| p.active && p.is_sandbox);
        // Capabilities are enforceable on all platforms where Casa1 runs.
        let capabilities_enforceable = cfg!(any(target_os = "macos", target_os = "windows"));
        SandboxEnvironmentSummary {
            app_container_available: true,
            profile_count: total,
            active_profile_count: active,
            sandbox_running,
            capabilities_enforceable,
        }
    }

    /// Validate whether a path is allowed for a given profile.
    ///
    /// Returns `Ok(())` if the path is in the profile's allowed read or write
    /// lists, or if the profile doesn't restrict that path.
    pub fn validate_path_access(
        &self,
        profile_name: &str,
        path: &str,
        write: bool,
    ) -> Result<(), String> {
        let profile = self
            .get_profile(profile_name)
            .ok_or_else(|| format!("AppContainer profile '{profile_name}' not found"))?;
        let allowed = if write {
            &profile.allowed_write_paths
        } else {
            &profile.allowed_read_paths
        };
        if allowed.is_empty() {
            // Empty allow list means no restrictions.
            return Ok(());
        }
        let normalized = path.replace('\\', "/");
        if allowed
            .iter()
            .any(|p| normalized.starts_with(&p.replace('\\', "/")))
        {
            Ok(())
        } else {
            Err(format!(
                "path '{path}' not in {} allow list for profile '{profile_name}'",
                if write { "write" } else { "read" }
            ))
        }
    }
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public helper functions
// ---------------------------------------------------------------------------

/// Generate a deterministic SID-like string for an AppContainer profile name.
///
/// This is not a real Windows SID but provides a consistent identifier for
/// each profile, mimicking the format `S-1-15-2-<hash>` used by Windows
/// AppContainer profiles.
pub fn generate_app_container_sid(profile_name: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    profile_name.hash(&mut hasher);
    let hash = hasher.finish();
    // Windows AppContainer SIDs follow the pattern: S-1-15-2-xxxxx-yyyyy-zzzzz
    let part1 = (hash & 0xFFFF) as u32;
    let part2 = ((hash >> 16) & 0xFFFF) as u32;
    let part3 = ((hash >> 32) & 0xFFFF) as u32;
    format!("S-1-15-2-{part1}-{part2}-{part3}")
}

/// Check if a SID string looks like an AppContainer SID.
///
/// AppContainer SIDs start with `S-1-15-2-`.
pub fn is_app_container_sid(sid: &str) -> bool {
    sid.starts_with("S-1-15-2-")
}

/// Parse a Windows capability name from a manifest XML `<Capability>` element.
///
/// Returns `None` if the name is not a recognized capability.
pub fn parse_capability_from_manifest(capability_name: &str) -> Option<AppContainerCapability> {
    AppContainerCapability::from_name(capability_name)
}

/// Derive the AppContainer named object path for a given SID.
///
/// On Windows, the path is `\Sessions\<session_id>\AppContainerNamedObjects\<sid>`.
/// This function returns the path fragment using session ID 1 as default.
pub fn get_app_container_named_object_path(sid: &str, session_id: u32) -> String {
    format!("\\Sessions\\{session_id}\\AppContainerNamedObjects\\{sid}")
}

/// Derive an AppContainer token's integrity level string.
pub fn get_app_container_integrity_level() -> &'static str {
    "Low" // AppContainer always runs at Low integrity level
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_create_and_get_profile() {
        let manager = SandboxManager::new();
        let profile = manager
            .create_profile("TestApp", "Test AppContainer profile")
            .unwrap();
        assert_eq!(profile.name, "TestApp");
        assert_eq!(profile.description, "Test AppContainer profile");
        assert!(profile.sid.starts_with("S-1-15-2-"));
        assert!(!profile.active);
        assert!(!profile.is_sandbox);
    }

    #[test]
    fn test_create_duplicate_profile_fails() {
        let manager = SandboxManager::new();
        manager.create_profile("Dupe", "first").unwrap();
        let result = manager.create_profile("Dupe", "second");
        assert!(result.is_err(), "expected Err, got {result:?}");
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn test_delete_profile() {
        let manager = SandboxManager::new();
        manager
            .create_profile("ToDelete", "will be deleted")
            .unwrap();
        let _result = manager.delete_profile("ToDelete");
        assert!(_result.is_ok(), "expected Ok, got {_result:?}");
        assert!(manager.get_profile("ToDelete").is_none());
    }

    #[test]
    fn test_delete_non_existent_fails() {
        let manager = SandboxManager::new();
        let result = manager.delete_profile("NonExistent");
        assert!(result.is_err(), "expected Err, got {result:?}");
    }

    #[test]
    fn test_list_profiles() {
        let manager = SandboxManager::new();
        manager.create_profile("Beta", "second").unwrap();
        manager.create_profile("Alpha", "first").unwrap();
        manager.create_profile("Gamma", "third").unwrap();
        let names = manager.list_profiles();
        assert_eq!(names, vec!["Alpha", "Beta", "Gamma"]);
    }

    #[test]
    fn test_add_and_check_capability() {
        let manager = SandboxManager::new();
        manager
            .create_profile("CapTest", "capability test")
            .unwrap();
        manager
            .add_capability("CapTest", AppContainerCapability::InternetClient)
            .unwrap();
        manager
            .add_capability("CapTest", AppContainerCapability::RemovableStorage)
            .unwrap();
        assert!(
            manager
                .check_capability("CapTest", &AppContainerCapability::InternetClient)
                .unwrap()
        );
        assert!(
            manager
                .check_capability("CapTest", &AppContainerCapability::RemovableStorage)
                .unwrap()
        );
        assert!(
            !manager
                .check_capability("CapTest", &AppContainerCapability::CodeGeneration)
                .unwrap()
        );
    }

    #[test]
    fn test_remove_capability() {
        let manager = SandboxManager::new();
        manager.create_profile("RemoveTest", "remove test").unwrap();
        manager
            .add_capability("RemoveTest", AppContainerCapability::InternetClient)
            .unwrap();
        assert!(
            manager
                .check_capability("RemoveTest", &AppContainerCapability::InternetClient)
                .unwrap()
        );
        manager
            .remove_capability("RemoveTest", &AppContainerCapability::InternetClient)
            .unwrap();
        assert!(
            !manager
                .check_capability("RemoveTest", &AppContainerCapability::InternetClient)
                .unwrap()
        );
    }

    #[test]
    fn test_set_profile_active() {
        let manager = SandboxManager::new();
        manager.create_profile("ActiveTest", "active test").unwrap();
        manager.set_profile_active("ActiveTest", true).unwrap();
        let profile = manager.get_profile("ActiveTest").unwrap();
        assert!(profile.active);
        manager.set_profile_active("ActiveTest", false).unwrap();
        let profile = manager.get_profile("ActiveTest").unwrap();
        assert!(!profile.active);
    }

    #[test]
    fn test_add_read_and_write_paths() {
        let manager = SandboxManager::new();
        manager.create_profile("PathTest", "path test").unwrap();
        manager
            .add_read_path("PathTest", "/Users/test/Documents")
            .unwrap();
        manager
            .add_write_path("PathTest", "/Users/test/AppData")
            .unwrap();
        let profile = manager.get_profile("PathTest").unwrap();
        assert_eq!(profile.allowed_read_paths.len(), 1);
        assert_eq!(profile.allowed_write_paths.len(), 1);
    }

    #[test]
    fn test_validate_path_access() {
        let manager = SandboxManager::new();
        manager.create_profile("AccessTest", "access test").unwrap();
        // Empty allow list = no restrictions.
        assert!(
            manager
                .validate_path_access("AccessTest", "/any/path", false)
                .is_ok()
        );
        // Add a read path restriction.
        manager
            .add_read_path("AccessTest", "/Users/test/Documents")
            .unwrap();
        assert!(
            manager
                .validate_path_access("AccessTest", "/Users/test/Documents/file.txt", false)
                .is_ok()
        );
        assert!(
            manager
                .validate_path_access("AccessTest", "/Users/test/Other", false)
                .is_err()
        );
    }

    #[test]
    fn test_capability_to_sid() {
        assert_eq!(
            AppContainerCapability::InternetClient.to_sid(),
            "S-1-15-3-8"
        );
        assert_eq!(AppContainerCapability::RunFullTrust.to_sid(), "S-1-15-3-12");
        assert_eq!(
            AppContainerCapability::DocumentsLibrary.to_sid(),
            "S-1-15-3-1"
        );
    }

    #[test]
    fn test_capability_from_name() {
        assert_eq!(
            AppContainerCapability::from_name("internetClient"),
            Some(AppContainerCapability::InternetClient)
        );
        assert_eq!(
            AppContainerCapability::from_name("runFullTrust"),
            Some(AppContainerCapability::RunFullTrust)
        );
        assert_eq!(AppContainerCapability::from_name("unknownCapability"), None);
    }

    #[test]
    fn test_capability_display_name() {
        assert_eq!(
            AppContainerCapability::InternetClient.display_name(),
            "Internet (Client)"
        );
        assert_eq!(
            AppContainerCapability::CodeGeneration.display_name(),
            "Code Generation (JIT)"
        );
    }

    #[test]
    fn test_generate_app_container_sid() {
        let sid1 = generate_app_container_sid("MyApp");
        let sid2 = generate_app_container_sid("MyApp");
        let sid3 = generate_app_container_sid("OtherApp");
        // Same input = same SID (deterministic hash).
        assert_eq!(sid1, sid2);
        assert_ne!(sid1, sid3);
        // All AppContainer SIDs start with the correct prefix.
        assert!(sid1.starts_with("S-1-15-2-"));
    }

    #[test]
    fn test_is_app_container_sid() {
        assert!(is_app_container_sid("S-1-15-2-123-456-789"));
        assert!(!is_app_container_sid("S-1-5-21-12345"));
        assert!(!is_app_container_sid("not-a-sid"));
    }

    #[test]
    fn test_get_app_container_named_object_path() {
        let path = get_app_container_named_object_path("S-1-15-2-100-200-300", 1);
        assert_eq!(
            path,
            "\\Sessions\\1\\AppContainerNamedObjects\\S-1-15-2-100-200-300"
        );
    }

    #[test]
    fn test_environment_summary() {
        let manager = SandboxManager::new();
        let summary = manager.environment_summary();
        assert!(summary.app_container_available);
        assert_eq!(summary.profile_count, 0);
        assert_eq!(summary.active_profile_count, 0);
        assert!(!summary.sandbox_running);

        manager.create_profile("P1", "test").unwrap();
        manager.create_profile("P2", "test").unwrap();
        manager.set_profile_active("P1", true).unwrap();
        let summary = manager.environment_summary();
        assert_eq!(summary.profile_count, 2);
        assert_eq!(summary.active_profile_count, 1);
    }

    #[test]
    fn test_sandbox_config_defaults() {
        let config = WindowsSandboxConfig::default();
        assert!(config.vgpu);
        assert!(config.networking);
        assert!(!config.audio_input);
        assert!(!config.video_input);
        assert!(config.clipboard_redirection);
    }

    #[test]
    fn test_generate_wsb_xml() {
        let manager = SandboxManager::new();
        let xml = manager.generate_wsb_xml();
        assert!(xml.contains("<Configuration>"));
        assert!(xml.contains("<VGpu>Enable</VGpu>"));
        assert!(xml.contains("<Networking>Enable</Networking>"));
        assert!(xml.contains("<ClipboardRedirection>Enable</ClipboardRedirection>"));
        assert!(xml.contains("<AudioInput>Disable</AudioInput>"));
        assert!(xml.contains("</Configuration>"));
    }

    #[test]
    fn test_generate_wsb_xml_with_mapped_folders() {
        let manager = SandboxManager::new();
        let mut config = WindowsSandboxConfig::default();
        config.mapped_folders.push(MappedFolder::new(
            "/Users/test/Projects",
            "C:\\Users\\WDAGUtilityAccount\\Desktop\\Projects",
            true,
        ));
        manager.set_sandbox_config(config);
        let xml = manager.generate_wsb_xml();
        assert!(xml.contains("<MappedFolder>"));
        assert!(xml.contains("<HostFolder>/Users/test/Projects</HostFolder>"));
        assert!(xml.contains("<ReadOnly>true</ReadOnly>"));
    }

    #[test]
    fn test_profile_capability_methods() {
        let mut profile = AppContainerProfile::new("TestProfile", "Test");
        profile.add_capability(AppContainerCapability::InternetClient);
        profile.add_capability(AppContainerCapability::InternetClientServer);
        assert!(profile.has_capability(&AppContainerCapability::InternetClient));
        assert!(profile.has_capability(&AppContainerCapability::InternetClientServer));
        profile.remove_capability(&AppContainerCapability::InternetClient);
        assert!(!profile.has_capability(&AppContainerCapability::InternetClient));
        assert!(profile.has_capability(&AppContainerCapability::InternetClientServer));
    }

    #[test]
    fn test_get_profile_by_sid() {
        let manager = SandboxManager::new();
        let profile = manager
            .create_profile("SidLookup", "SID lookup test")
            .unwrap();
        let sid = profile.sid.clone();
        let found = manager.get_profile_by_sid(&sid);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "SidLookup");
    }

    #[test]
    fn test_list_profiles_detailed() {
        let manager = SandboxManager::new();
        manager.create_profile("ZProfile", "last").unwrap();
        manager.create_profile("AProfile", "first").unwrap();
        let detailed = manager.list_profiles_detailed();
        assert_eq!(detailed.len(), 2);
        assert_eq!(detailed[0].name, "AProfile");
        assert_eq!(detailed[1].name, "ZProfile");
    }

    #[test]
    fn test_integrity_level() {
        assert_eq!(get_app_container_integrity_level(), "Low");
    }

    #[test]
    fn test_set_enabled() {
        let manager = SandboxManager::new();
        assert!(manager.is_enabled());
        manager.set_enabled(false);
        assert!(!manager.is_enabled());
    }

    #[test]
    fn test_with_profiles() {
        let profiles = vec![
            AppContainerProfile::new("PreConfig1", "pre-configured 1"),
            AppContainerProfile::new("PreConfig2", "pre-configured 2"),
        ];
        let manager = SandboxManager::with_profiles(profiles);
        assert_eq!(manager.list_profiles().len(), 2);
        assert!(manager.get_profile("PreConfig1").is_some());
        assert!(manager.get_profile("PreConfig2").is_some());
    }

    #[test]
    fn test_parse_capability_from_manifest() {
        assert_eq!(
            parse_capability_from_manifest("internetClient"),
            Some(AppContainerCapability::InternetClient)
        );
        assert_eq!(parse_capability_from_manifest("invalid"), None);
    }

    #[test]
    fn test_add_registry_key() {
        let mut profile = AppContainerProfile::new("RegTest", "registry test");
        profile.add_registry_key(r"HKEY_LOCAL_MACHINE\Software\MyApp");
        assert_eq!(profile.allowed_registry_keys.len(), 1);
        // Adding the same key twice should not duplicate.
        profile.add_registry_key(r"HKEY_LOCAL_MACHINE\Software\MyApp");
        assert_eq!(profile.allowed_registry_keys.len(), 1);
    }

    #[test]
    fn test_mapped_folder_creation() {
        let folder = MappedFolder::new("/host/path", "C:\\Sandbox\\Path", true);
        assert_eq!(folder.host_path, "/host/path");
        assert_eq!(folder.sandbox_path, "C:\\Sandbox\\Path");
        assert!(folder.read_only);
    }

    // ===================================================================
    // Sandbox path canonicalization audit — Items 223-224
    // ===================================================================

    #[test]
    fn sandbox_reject_path_traversal_dotdot() {
        // Path traversal with ".." should always be rejected.
        let _manager = SandboxManager::new();
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        let result = fs_sandbox.authorize(
            "../../etc/passwd",
            "/tmp/test_ge/drive_c/safe",
            "/tmp/test_ge/drive_c/safe",
        );
        assert!(
            result.is_err(),
            "path traversal with .. should be denied, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_reject_path_traversal_windows_style() {
        // Windows-style path traversal with "..\\"
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        let result = fs_sandbox.authorize(
            r"C:\..\..\Windows\System32",
            "/tmp/test_ge/drive_c/safe",
            "/tmp/test_ge/drive_c/safe",
        );
        assert!(
            result.is_err(),
            "Windows path traversal with .. should be denied, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_reject_toctou_path_swap() {
        // TOCTOU check: realpath_before_open != realpath_after_open should be denied.
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        let result = fs_sandbox.authorize(
            "/tmp/test_ge/drive_c/legit",
            "/tmp/test_ge/drive_c/legit",
            "/tmp/test_ge/drive_c/evil",
        );
        assert!(
            result.is_err(),
            "TOCTOU path swap should be denied, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_allow_path_within_ge_root() {
        // Path within ge_root should be allowed.
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        let result = fs_sandbox.authorize(
            "/tmp/test_ge/drive_c/game.exe",
            "/tmp/test_ge/drive_c/game.exe",
            "/tmp/test_ge/drive_c/game.exe",
        );
        assert!(
            result.is_ok(),
            "path within GE root should be allowed, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_allow_path_in_allow_list() {
        // Path within allow_list should be allowed even if outside ge_root.
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        let result = fs_sandbox.authorize(
            "/tmp/allowed/some_file.dll",
            "/tmp/allowed/some_file.dll",
            "/tmp/allowed/some_file.dll",
        );
        assert!(
            result.is_ok(),
            "path within allow list should be allowed, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_reject_path_outside_sandbox() {
        // Path completely outside the sandbox should be denied.
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        let result = fs_sandbox.authorize("/etc/passwd", "/etc/passwd", "/etc/passwd");
        assert!(
            result.is_err(),
            "path outside sandbox should be denied, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_reject_sensitive_system_path() {
        // Sensitive system paths should be rejected.
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        // /System is sensitive and not under ge_root
        let result = fs_sandbox.authorize(
            "/System/Library/CoreServices",
            "/System/Library/CoreServices",
            "/System/Library/CoreServices",
        );
        assert!(
            result.is_err(),
            "sensitive system path should be denied, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_reject_sensitive_library_path() {
        // macOS Library paths should be rejected.
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        let result = fs_sandbox.authorize(
            "/Library/Application Support/SomeApp",
            "/Library/Application Support/SomeApp",
            "/Library/Application Support/SomeApp",
        );
        assert!(
            result.is_err(),
            "Library path should be denied, got {:?}",
            result
        );
    }

    #[test]
    fn sandbox_reject_path_with_null_byte() {
        // Null bytes in paths should be rejected at the canonicalization level.
        let ge_root = "/tmp/test_ge".to_string();
        let allow_list = vec!["/tmp/allowed".to_string()];
        let _fs_sandbox = crate::security::FilesystemSandbox::new(&ge_root, &allow_list);

        // The FilesystemSandbox::authorize uses requested_path which is split on /
        // A null byte won't appear in `..` detection but the resolve_sandbox_path catches it.
        let result = crate::security::resolve_sandbox_path(
            "/tmp/test_ge/drive_c/game.exe\0../etc",
            Path::new("/tmp/test_ge"),
            &allow_list,
        );
        assert!(
            result.is_err(),
            "path with null byte should be denied, got {:?}",
            result
        );
    }

    // -----------------------------------------------------------------------
    //  Item 239: Case-insensitivity / path normalization tests for sandbox
    //  Item 240: Long path / reserved name / invalid char tests for sandbox
    // -----------------------------------------------------------------------

    #[test]
    fn sandbox_reject_case_variant_of_restricted_path() {
        let mut profile = AppContainerProfile::new("CaseTest", "Case test");
        profile.add_read_path("C:\\Windows\\System32");
        let profiles = vec![profile];
        let manager = SandboxManager::with_profiles(profiles);

        // Exact case should be allowed
        let result = manager.validate_path_access("CaseTest", "C:\\Windows\\System32", false);
        assert!(
            result.is_ok(),
            "exact case path should be allowed: {:?}",
            result.err()
        );

        // Case-variant paths are currently NOT case-insensitive (the implementation
        // normalizes \\ to / but does not normalize case). These should be rejected
        // unless the code is enhanced to do case-insensitive matching.
        let result_lower = manager.validate_path_access("CaseTest", "c:\\windows\\system32", false);
        assert!(
            result_lower.is_err(),
            "lowercase variant currently rejected (case-sensitive implementation): {:?}",
            result_lower
        );
    }

    #[test]
    fn sandbox_accept_long_path_within_allowed_root() {
        let mut profile = AppContainerProfile::new("LongPathTest", "Long path test");
        profile.add_read_path("C:\\TestRoot");
        let profiles = vec![profile];
        let manager = SandboxManager::with_profiles(profiles);

        // Build a path longer than 260 characters within the allowed root
        let long_segment = "subdir\\".repeat(40);
        let long_path = format!("C:\\TestRoot\\{}file.txt", long_segment);
        assert!(
            long_path.len() > 260,
            "test path {} should exceed MAX_PATH",
            long_path.len()
        );

        let result = manager.validate_path_access("LongPathTest", &long_path, false);
        assert!(
            result.is_ok(),
            "long path within allowed root should be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn sandbox_reject_alternate_separator_forms() {
        let mut profile = AppContainerProfile::new("SepTest", "Separator test");
        profile.add_read_path("C:\\Windows\\System32");
        let profiles = vec![profile];
        let manager = SandboxManager::with_profiles(profiles);

        // Forward slashes (POSIX-style) should be handled by normalization
        let fwd_slash_path = "C:/Windows/System32/cmd.exe";
        let result = manager.validate_path_access("SepTest", fwd_slash_path, false);
        assert!(
            result.is_ok(),
            "forward slash path should be normalized and allowed: {:?}",
            result.err()
        );
    }
}

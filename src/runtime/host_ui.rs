//! Host message-box/beep and trace helpers.

use super::*;

/// Stage a message box request for [`crate::runtime::message_box_response`].
///
/// The dispatch site calls this immediately before `message_box_response`,
/// which owns the style-dependent button set, the dialog and the button
/// parsing.  Staging (rather than showing an OK-only box here) keeps the
/// displayed buttons and the returned ID derived from one style value and
/// removes the previous one-second auto-OK.
pub(crate) fn show_host_message_box(title: &str, text: &str, dtm: bool) -> AppResult<()> {
    PENDING_MESSAGE_BOX.with(|pending| {
        *pending.borrow_mut() = Some((title.to_string(), text.to_string(), dtm));
    });
    Ok(())
}

thread_local! {
    static PENDING_MESSAGE_BOX: std::cell::RefCell<Option<(String, String, bool)>> =
        const { std::cell::RefCell::new(None) };
}

/// Take the staged message box payload, if any.  The payload is per-thread
/// because the guest dispatch and its immediate `message_box_response` call
/// run on the same runtime owner thread.
pub(crate) fn take_pending_message_box() -> Option<(String, String, bool)> {
    PENDING_MESSAGE_BOX.with(|pending| pending.borrow_mut().take())
}

pub(crate) fn play_host_beep(frequency_hz: u32, duration_ms: u32, dtm: bool) -> AppResult<()> {
    if dtm {
        return Ok(());
    }
    let temp_path = std::env::temp_dir().join(format!(
        "casa1-beep-{}-{}.wav",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0)
    ));
    let wav = synthesize_beep_wav(frequency_hz.max(37), duration_ms.max(10));
    fs::write(&temp_path, wav).map_err(|error| {
        AppError::from_io(
            ReasonCode::RcIo,
            format!("failed to write host beep WAV {}", temp_path.display()),
            &error,
        )
    })?;
    let status = Command::new("afplay")
        .arg(&temp_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| {
            AppError::from_io(ReasonCode::RcIo, "failed to launch afplay for Beep", &error)
        })?;
    let _ = fs::remove_file(&temp_path);
    if !status.success() {
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("afplay failed while playing Beep: {status}"),
        ));
    }
    Ok(())
}

pub(crate) fn synthesize_beep_wav(frequency_hz: u32, duration_ms: u32) -> Vec<u8> {
    let sample_rate = 44_100_u32;
    let samples = ((sample_rate as u64 * duration_ms as u64) / 1000) as usize;
    let mut pcm = Vec::with_capacity(samples * 2);
    let amplitude = i16::MAX as f32 * 0.2;
    for index in 0..samples {
        let phase =
            (index as f32 * frequency_hz as f32 * std::f32::consts::TAU) / sample_rate as f32;
        let sample = (phase.sin() * amplitude) as i16;
        pcm.extend_from_slice(&sample.to_le_bytes());
    }

    let data_len = pcm.len() as u32;
    let mut wav = Vec::with_capacity(44 + pcm.len());
    wav.extend_from_slice(b"RIFF");
    wav.extend_from_slice(&(36 + data_len).to_le_bytes());
    wav.extend_from_slice(b"WAVEfmt ");
    wav.extend_from_slice(&16_u32.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&1_u16.to_le_bytes());
    wav.extend_from_slice(&sample_rate.to_le_bytes());
    wav.extend_from_slice(&(sample_rate * 2).to_le_bytes());
    wav.extend_from_slice(&2_u16.to_le_bytes());
    wav.extend_from_slice(&16_u16.to_le_bytes());
    wav.extend_from_slice(b"data");
    wav.extend_from_slice(&data_len.to_le_bytes());
    wav.extend_from_slice(&pcm);
    wav
}

pub(crate) fn apple_script_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

// ---------------------------------------------------------------------------
// HostOpen — the single checked classifier for guest-requested shell opens
//
// Every guest path that reaches the host shell (`ShellExecuteW`,
// `ShellExecuteExW`, `IContextMenu::InvokeCommand`, the CEF query bridge)
// is reduced to a [`HostOpenPlan`] here: allowlisted URL schemes only,
// file targets resolved through `win32::guest_path_to_host_path` (never a
// raw guest string), blocked code/launcher extensions refused, directories
// revealed with `open -R`, and the resolved value handed to `/usr/bin/open`.
// Rejections surface as [`SE_ERR_ACCESSDENIED`] — a failure is never
// reported as success.
// ---------------------------------------------------------------------------

/// `SE_ERR_ACCESSDENIED`: the `ShellExecute*` failure value (and Win32
/// `ERROR_ACCESS_DENIED`) returned when the classifier refuses a target.
pub(crate) const SE_ERR_ACCESSDENIED: u64 = 5;

/// Extensions the guest may never have opened by the host shell.  Each
/// entry is a launcher, interpreter, installer or code bundle that macOS
/// would execute or load rather than merely display.
const BLOCKED_HOST_OPEN_EXTENSIONS: &[&str] = &[
    "app",
    "command",
    "tool",
    "terminal",
    "sh",
    "zsh",
    "bash",
    "workflow",
    "scpt",
    "applescript",
    "pkg",
    "mpkg",
    "dmg",
    "dylib",
    "kext",
    "webloc",
    "inetloc",
    "fileloc",
];

/// URL schemes the guest may ask the host shell to open.
const ALLOWED_HOST_OPEN_SCHEMES: [&str; 3] = ["http", "https", "mailto"];

/// A classified, host-safe shell-open request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostOpenPlan {
    /// Empty target: nothing to open, success without spawning anything.
    Nothing,
    /// An allowlisted URL (`http`/`https`/`mailto`).
    Url(String),
    /// A host path resolved from the guest path; `reveal` selects the
    /// `open -R` reveal form (directories and the `explore` verb).
    Path { path: PathBuf, reveal: bool },
}

/// Why the checked classifier refused a shell-open target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostOpenReject {
    /// `..` component in a path target (traversal outside the GE).
    Traversal,
    /// URL scheme outside `http`/`https`/`mailto`.
    UnsupportedScheme(String),
    /// File extension on the code/launcher block list.
    BlockedExtension(String),
    /// The guest path could not be resolved inside the GE sandbox.
    Unresolvable(String),
}

impl HostOpenReject {
    /// Stable short reason for traces and error responses.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Traversal => "path traversal refused",
            Self::UnsupportedScheme(_) => "url scheme outside http/https/mailto",
            Self::BlockedExtension(_) => "blocked file extension",
            Self::Unresolvable(_) => "guest path did not resolve inside the GE",
        }
    }

    /// Detail string carrying the offending value (already host-side data).
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Traversal => "traversal".to_string(),
            Self::UnsupportedScheme(scheme) => scheme.clone(),
            Self::BlockedExtension(extension) => extension.clone(),
            Self::Unresolvable(message) => message.clone(),
        }
    }
}

/// Failure of the host-open executor (after classification succeeded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostOpenError {
    /// The guest file could not be quarantined; opening is refused.
    Quarantine(String),
    /// `/usr/bin/open` could not be spawned.
    Spawn(String),
}

impl HostOpenError {
    /// Stable short reason for traces and error responses.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Quarantine(_) => "guest file could not be quarantined",
            Self::Spawn(_) => "host open program failed to start",
        }
    }

    /// Detail string carrying the underlying host error.
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::Quarantine(message) | Self::Spawn(message) => message.clone(),
        }
    }
}

/// Classify one raw shell-open target.
///
/// `resolve` maps a guest path string to its host path through
/// `win32::guest_path_to_host_path`; it is never called for URL targets and
/// never called with a traversal target, so an untrusted string can only
/// reach the host filesystem through the sandboxed resolver.
pub(crate) fn classify_host_open_target(
    target: &str,
    resolve: impl FnOnce(&str) -> AppResult<PathBuf>,
) -> Result<HostOpenPlan, HostOpenReject> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Ok(HostOpenPlan::Nothing);
    }
    if let Some(scheme) = url_scheme(trimmed) {
        return if ALLOWED_HOST_OPEN_SCHEMES.contains(&scheme.as_str()) {
            Ok(HostOpenPlan::Url(trimmed.to_string()))
        } else {
            Err(HostOpenReject::UnsupportedScheme(scheme))
        };
    }
    // Refuse `..` before anything touches the filesystem: the GE resolver
    // canonicalizes only existing ancestors, so an unnormalized target
    // containing `..` would otherwise be handed to `open` verbatim.
    if trimmed
        .split(['/', '\\'])
        .any(|component| component == "..")
    {
        return Err(HostOpenReject::Traversal);
    }
    let path = resolve(trimmed).map_err(|error| HostOpenReject::Unresolvable(error.message))?;
    if let Some(extension) = blocked_extension(&path) {
        return Err(HostOpenReject::BlockedExtension(extension));
    }
    let reveal = path.is_dir();
    Ok(HostOpenPlan::Path { path, reveal })
}

/// Extract a URL scheme from a target, or `None` for filesystem paths.
///
/// A single-letter head (`C:\x`, `C:/x`, `C:stream`) is a drive prefix and
/// is never treated as a scheme; anything that is not a syntactically valid
/// scheme is treated as a path.
fn url_scheme(target: &str) -> Option<String> {
    let colon = target.find(':')?;
    let head = &target[..colon];
    if head.len() == 1 && head.as_bytes()[0].is_ascii_alphabetic() {
        return None;
    }
    let mut bytes = head.bytes();
    let first = bytes.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let valid =
        bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
    valid.then(|| head.to_ascii_lowercase())
}

/// The lowercased trailing extension of a path, when it is on the block
/// list.  Trailing spaces/dots are stripped first (Windows tolerates them,
/// so `evil.sh ` must not slip through).
fn blocked_extension(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy();
    let name = name.trim_end_matches([' ', '.']);
    let (_, extension) = name.rsplit_once('.')?;
    let extension = extension.trim().to_ascii_lowercase();
    BLOCKED_HOST_OPEN_EXTENSIONS
        .contains(&extension.as_str())
        .then_some(extension)
}

/// Set the macOS quarantine xattr on a guest-created file so the host shell
/// cannot open it without Gatekeeper review.  Fails closed: a file that
/// cannot be quarantined is never opened.
pub(crate) fn quarantine_guest_file(path: &Path) -> AppResult<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    // Same payload shape as the real filesystem quarantine writer.
    let quarantine_data = format!("Casa1;{timestamp:x};{}", uuid::Uuid::new_v4().simple());
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|error| {
        AppError::new(
            ReasonCode::RcIo,
            format!("invalid quarantine path: {error}"),
        )
    })?;
    // The xattr name is a compile-time C literal: it can never embed a NUL.
    let c_name = c"com.apple.quarantine";
    // SAFETY: `setxattr` FFI — both CStrings are NUL-terminated, the value
    // pointer/length describe `quarantine_data`, and flags=0 is valid.
    let result = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            quarantine_data.as_ptr().cast::<std::ffi::c_void>(),
            quarantine_data.len(),
            0,
            0,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        return Err(AppError::new(
            ReasonCode::RcIo,
            format!("quarantine xattr failed for {}: {error}", path.display()),
        ));
    }
    Ok(())
}

/// Spawn `/usr/bin/open` for an already-classified plan and reap the child
/// on a background thread (the guest thread never blocks on the child).
pub(crate) fn spawn_host_open(program: &Path, plan: &HostOpenPlan) -> Result<(), HostOpenError> {
    let mut command = match plan {
        HostOpenPlan::Nothing => return Ok(()),
        HostOpenPlan::Url(url) => {
            let mut command = Command::new(program);
            command.arg(url);
            command
        }
        HostOpenPlan::Path { path, reveal } => {
            if path.is_file() {
                quarantine_guest_file(path)
                    .map_err(|error| HostOpenError::Quarantine(error.message))?;
            }
            let mut command = Command::new(program);
            if *reveal {
                command.arg("-R");
            }
            command.arg(path);
            command
        }
    };
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let child = command
        .spawn()
        .map_err(|error| HostOpenError::Spawn(error.to_string()))?;
    let _ = spawn_reaper(child);
    Ok(())
}

/// Hand the child to a detached reaper thread; returns the join handle so
/// tests can wait for the reap deterministically.
pub(crate) fn spawn_reaper(
    child: std::process::Child,
) -> std::thread::JoinHandle<Option<std::process::ExitStatus>> {
    std::thread::spawn(move || reap_open_child(child))
}

/// Reap a host-open child so no zombie is left behind.
pub(crate) fn reap_open_child(child: std::process::Child) -> Option<std::process::ExitStatus> {
    let mut child = child;
    child.wait().ok()
}

/// The host program used for checked opens (`/usr/bin/open`).
///
/// Test builds may redirect it (see [`set_host_open_program_override`]) so
/// no test can launch a browser, Finder window or text editor.
pub(crate) fn host_open_program() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(program) = HOST_OPEN_PROGRAM_OVERRIDE.with(|slot| slot.borrow().clone()) {
            return program;
        }
    }
    PathBuf::from("/usr/bin/open")
}

#[cfg(test)]
thread_local! {
    /// Test-only redirect of the host open program.
    static HOST_OPEN_PROGRAM_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_host_open_program_override(program: Option<PathBuf>) {
    HOST_OPEN_PROGRAM_OVERRIDE.with(|slot| *slot.borrow_mut() = program);
}

pub(crate) fn trace_event(
    event_index: u64,
    category: &str,
    call_id: &str,
    parameters: BTreeMap<String, Value>,
    return_value: Value,
    side_effect_hashes: Vec<String>,
) -> TraceEvent {
    TraceEvent {
        event_index,
        category: category.to_string(),
        call_id: call_id.to_string(),
        parameters,
        return_value,
        get_last_error: None,
        side_effect_hashes,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_open_classifier_rejects_every_blocked_extension_exactly() {
        for extension in [
            "sh", "SH", "app", "tool", "dylib", "pkg", "dmg", "webloc", "scpt",
        ] {
            let target = format!("C:\\game\\payload.{extension}");
            let resolved = PathBuf::from(format!("/ge/drive_c/game/payload.{extension}"));
            let outcome = classify_host_open_target(&target, |_| Ok(resolved.clone()));
            assert_eq!(
                outcome,
                Err(HostOpenReject::BlockedExtension(
                    extension.to_ascii_lowercase()
                )),
                "extension {extension} must be refused"
            );
        }
        // Trailing dots/spaces are stripped before the extension test, so
        // `evil.sh.` and `evil.sh ` cannot slip past the block list.
        for resolved in ["/ge/drive_c/game/evil.sh.", "/ge/drive_c/game/evil.sh "] {
            let outcome =
                classify_host_open_target("C:\\game\\evil.sh", |_| Ok(PathBuf::from(resolved)));
            assert_eq!(
                outcome,
                Err(HostOpenReject::BlockedExtension("sh".to_string()))
            );
        }
        // A plain document stays openable.
        let allowed = classify_host_open_target("C:\\game\\notes.txt", |_| {
            Ok(PathBuf::from("/ge/drive_c/game/notes.txt"))
        });
        assert_eq!(
            allowed,
            Ok(HostOpenPlan::Path {
                path: PathBuf::from("/ge/drive_c/game/notes.txt"),
                reveal: false,
            })
        );
    }

    #[test]
    fn host_open_classifier_refuses_traversal_targets_before_resolution() {
        for target in [
            "C:\\game\\..\\..\\evil.exe",
            "C:/game/../../evil.exe",
            "..\\..\\evil.exe",
            "/tmp/../etc/passwd",
            "C:\\game\\sub\\..",
        ] {
            let outcome = classify_host_open_target(target, |_| {
                panic!("the sandbox resolver must not run for a traversal target")
            });
            assert_eq!(outcome, Err(HostOpenReject::Traversal), "target {target}");
        }
    }

    #[test]
    fn host_open_classifier_allows_only_http_and_mailto_url_schemes() {
        for target in [
            "https://example.com/a",
            "http://example.com/a",
            "mailto:someone@example.com",
        ] {
            let outcome = classify_host_open_target(target, |_| {
                panic!("URL targets never reach the sandbox resolver")
            });
            assert_eq!(outcome, Ok(HostOpenPlan::Url(target.to_string())));
        }
        for (target, scheme) in [
            ("javascript:alert(1)", "javascript"),
            ("file:///etc/passwd", "file"),
            ("steam://run/480", "steam"),
            ("smb://server/share", "smb"),
            ("data:text/html,x", "data"),
        ] {
            let outcome = classify_host_open_target(target, |_| {
                panic!("URL targets never reach the sandbox resolver")
            });
            assert_eq!(
                outcome,
                Err(HostOpenReject::UnsupportedScheme(scheme.to_string()))
            );
        }
        // A drive-letter path is never mistaken for a URL scheme.
        let drive = classify_host_open_target("C:\\game\\note.txt", |_| {
            Ok(PathBuf::from("/ge/drive_c/game/note.txt"))
        });
        assert_eq!(
            drive,
            Ok(HostOpenPlan::Path {
                path: PathBuf::from("/ge/drive_c/game/note.txt"),
                reveal: false,
            })
        );
    }

    #[test]
    fn host_open_classifier_surfaces_resolution_failure_and_reveals_directories() {
        let unresolved = classify_host_open_target("\\\\server\\share\\x.txt", |_| {
            Err(AppError::new(
                ReasonCode::RcFsSandboxEscape,
                "drive C is not enabled",
            ))
        });
        assert_eq!(
            unresolved,
            Err(HostOpenReject::Unresolvable(
                "drive C is not enabled".to_string()
            ))
        );

        let empty = classify_host_open_target("   ", |_| {
            panic!("an empty target never reaches the resolver")
        });
        assert_eq!(empty, Ok(HostOpenPlan::Nothing));

        let temp = tempfile::TempDir::new().expect("temp dir");
        let directory = classify_host_open_target("C:\\game", |_| Ok(temp.path().to_path_buf()));
        assert_eq!(
            directory,
            Ok(HostOpenPlan::Path {
                path: temp.path().to_path_buf(),
                reveal: true,
            })
        );

        let missing =
            classify_host_open_target("C:\\game\\gone.txt", |_| Ok(temp.path().join("gone.txt")));
        assert_eq!(
            missing,
            Ok(HostOpenPlan::Path {
                path: temp.path().join("gone.txt"),
                reveal: false,
            })
        );
    }

    #[test]
    fn host_open_spawn_failure_and_success_paths_are_exact() {
        // A `Nothing` plan succeeds without spawning anything.
        assert_eq!(
            spawn_host_open(Path::new("/nonexistent/casa1-open"), &HostOpenPlan::Nothing),
            Ok(())
        );
        // A program that does not exist is reported, never swallowed.
        let failure = spawn_host_open(
            Path::new("/nonexistent/casa1-open"),
            &HostOpenPlan::Url("https://example.com".to_string()),
        );
        assert_eq!(
            failure.err().map(|error| error.reason()),
            Some("host open program failed to start")
        );

        // The success path (file + reveal) runs against a harmless stand-in
        // program so no test can open a browser, Finder or editor window.
        set_host_open_program_override(Some(PathBuf::from("/usr/bin/true")));
        let program = host_open_program();
        let temp = tempfile::TempDir::new().expect("temp dir");
        let absent = temp.path().join("absent.txt");
        assert_eq!(
            spawn_host_open(
                &program,
                &HostOpenPlan::Path {
                    path: absent.clone(),
                    reveal: false
                }
            ),
            Ok(())
        );
        assert_eq!(
            spawn_host_open(
                &program,
                &HostOpenPlan::Path {
                    path: absent,
                    reveal: true
                }
            ),
            Ok(())
        );
        let present = temp.path().join("present.txt");
        fs::write(&present, b"guest bytes").expect("write guest file");
        assert_eq!(
            spawn_host_open(
                &program,
                &HostOpenPlan::Path {
                    path: present.clone(),
                    reveal: false
                }
            ),
            Ok(())
        );
        let mut buffer = [0_u8; 128];
        let c_path = std::ffi::CString::new(present.as_os_str().as_encoded_bytes()).expect("path");
        let c_name =
            std::ffi::CString::new(crate::real_fs::XATTR_COM_APPLE_QUARANTINE).expect("name");
        let read = unsafe {
            libc::getxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                0,
            )
        };
        assert_ne!(
            read, -1,
            "spawning an open for a guest file must quarantine it first"
        );
        set_host_open_program_override(None);
    }

    #[test]
    fn host_open_quarantine_fails_closed_for_a_missing_guest_file() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let missing = temp.path().join("absent.txt");
        let outcome = quarantine_guest_file(&missing);
        assert_eq!(
            outcome.err().map(|error| error.code),
            Some(ReasonCode::RcIo)
        );
    }

    #[test]
    fn host_open_reject_reasons_and_details_cover_every_variant_boundary() {
        for (reject, reason, detail) in [
            (
                HostOpenReject::Traversal,
                "path traversal refused",
                "traversal".to_string(),
            ),
            (
                HostOpenReject::UnsupportedScheme("steam".to_string()),
                "url scheme outside http/https/mailto",
                "steam".to_string(),
            ),
            (
                HostOpenReject::BlockedExtension("sh".to_string()),
                "blocked file extension",
                "sh".to_string(),
            ),
            (
                HostOpenReject::Unresolvable("drive missing".to_string()),
                "guest path did not resolve inside the GE",
                "drive missing".to_string(),
            ),
        ] {
            assert_eq!(reject.reason(), reason);
            assert_eq!(reject.detail(), detail);
        }
        for (error, reason, detail) in [
            (
                HostOpenError::Quarantine("xattr failed".to_string()),
                "guest file could not be quarantined",
                "xattr failed".to_string(),
            ),
            (
                HostOpenError::Spawn("not found".to_string()),
                "host open program failed to start",
                "not found".to_string(),
            ),
        ] {
            assert_eq!(error.reason(), reason);
            assert_eq!(error.detail(), detail);
        }
    }

    #[test]
    fn host_open_url_scheme_parser_rejects_invalid_scheme_boundaries() {
        // A head that is not an ASCII letter is a path, never a scheme.
        assert_eq!(url_scheme("1http://example.com"), None);
        assert_eq!(url_scheme(":no-head"), None);
        // A single-letter head is a Windows drive prefix.
        assert_eq!(url_scheme("C:\\game\\x.txt"), None);
        // Valid scheme characters are accepted and lowercased.
        assert_eq!(
            url_scheme("HTTP+ext-1.0://x"),
            Some("http+ext-1.0".to_string())
        );
        // No colon at all is a path.
        assert_eq!(url_scheme("C:\\game"), None);
    }

    #[test]
    fn host_open_quarantine_rejects_nul_path_without_touching_the_filesystem() {
        use std::os::unix::ffi::OsStrExt;
        let path = Path::new(std::ffi::OsStr::from_bytes(b"/tmp/casa1\0escape"));
        let error = quarantine_guest_file(path).expect_err("NUL path must be refused");
        assert_eq!(error.code, ReasonCode::RcIo);
        assert!(error.message.starts_with("invalid quarantine path: "));
        assert_eq!(
            crate::real_fs::XATTR_COM_APPLE_QUARANTINE.as_bytes(),
            b"com.apple.quarantine"
        );
    }

    #[test]
    fn host_open_reaper_worker_joins_the_child_without_leaking_a_zombie() {
        let child = Command::new("/usr/bin/true").spawn().expect("spawn true");
        let handle = spawn_reaper(child);
        let status = handle.join().expect("reaper thread must not panic");
        assert_eq!(status.map(|status| status.code()), Some(Some(0)));
    }
}

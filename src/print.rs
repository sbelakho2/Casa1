use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Printer handle type
pub type PrinterHandle = u64;

/// Maximum spool bytes retained per job. The cap prevents unbounded
/// guest-driven memory growth; bytes past the cap are dropped.
const MAX_SPOOL_BYTES: usize = 64 * 1024 * 1024;

/// Generated PDFs go under the OS temp directory, never into the invoking
/// user's real `~/Documents` (the previous behaviour polluted developer
/// machines during tests and guest runs).
const PRINT_OUTPUT_DIR: &str = "casa1-prints";

/// Maximum number of completed jobs retained for status queries; older
/// completed jobs are evicted so spool data cannot accumulate forever.
const MAX_RETAINED_JOBS: usize = 32;

/// Print job status
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrintJobStatus {
    Idle,
    Spooling,
    Printing,
    Completed,
    Deleted,
}

/// Print job handle type
pub struct PrintJob {
    pub id: u32,
    pub printer_handle: PrinterHandle,
    pub document_name: String,
    pub spool_data: Vec<u8>,
    pub page_count: u32,
    pub status: PrintJobStatus,
    pub started: std::time::Instant,
}

/// Printer information
pub struct PrinterInfo {
    pub name: String,
    pub port: String,
    pub driver: String,
    pub comment: String,
    pub location: String,
    pub status: u32,
    pub attributes: u32,
    pub jobs: u32,
    pub default_priority: u32,
}

/// Printer DC handle type — used for GDI printer DC simulation
pub type PrinterDcHandle = u64;

/// State held for a GDI printer DC
pub struct PrinterDc {
    pub handle: PrinterDcHandle,
    pub printer_name: String,
}

/// Print subsystem state
pub struct PrintSubsystem {
    pub printers: HashMap<PrinterHandle, PrinterInfo>,
    pub jobs: HashMap<u32, PrintJob>,
    pub next_handle: PrinterHandle,
    pub next_job_id: u32,
    pub printer_dcs: HashMap<PrinterDcHandle, PrinterDc>,
    pub next_dc_handle: PrinterDcHandle,
    /// Active print jobs keyed by job ID, each with the printer handle that
    /// owns it. Per-handle state means ending or closing one job cannot
    /// silently cancel another job (including another job on the same
    /// printer), and a printer lookup returns its most recent live job.
    pub active_jobs: HashMap<u32, PrinterHandle>,
}

impl PrintSubsystem {
    pub fn new() -> Self {
        let mut printers = HashMap::new();
        // Add default "Microsoft Print to PDF" printer
        printers.insert(1, default_printer_info());
        PrintSubsystem {
            printers,
            jobs: HashMap::new(),
            next_handle: 2,
            next_job_id: 1,
            printer_dcs: HashMap::new(),
            next_dc_handle: 0x2000,
            active_jobs: HashMap::new(),
        }
    }

    pub fn open_printer(&mut self, name: Option<&str>) -> Option<PrinterHandle> {
        // Find printer by name, or return default
        let printer_name = name.unwrap_or("Microsoft Print to PDF");
        for (&handle, info) in &self.printers {
            if info.name == printer_name {
                return Some(handle);
            }
        }
        if name.is_none() {
            // The default printer was deleted; restore it so a printer-less
            // guest keeps working instead of failing every open.
            let handle = self.next_handle;
            self.next_handle = self.next_handle.wrapping_add(1);
            self.printers.insert(handle, default_printer_info());
            return Some(handle);
        }
        None
    }

    pub fn close_printer(&mut self, handle: PrinterHandle) -> bool {
        // Unknown handles are not silently accepted: Win32 ClosePrinter must
        // fail for a handle this subsystem never issued.
        if !self.printers.contains_key(&handle) {
            return false;
        }
        // Cancel only jobs owned by THIS handle; jobs on other handles stay
        // intact. Closing one printer must never cancel another's spool.
        let owned: Vec<u32> = self
            .active_jobs
            .iter()
            .filter(|(_, owner)| **owner == handle)
            .map(|(job_id, _)| *job_id)
            .collect();
        for job_id in owned {
            self.active_jobs.remove(&job_id);
            self.jobs.remove(&job_id);
        }
        true
    }

    pub fn start_doc_printer(
        &mut self,
        printer_handle: PrinterHandle,
        doc_name: &str,
    ) -> Option<u32> {
        if !self.printers.contains_key(&printer_handle) {
            return None;
        }
        // Guard against wrap-around/collision of the u32 job-id space.
        let job_id = self.next_job_id;
        if job_id == 0 || self.jobs.contains_key(&job_id) {
            return None;
        }
        self.next_job_id = self.next_job_id.wrapping_add(1);
        self.jobs.insert(
            job_id,
            PrintJob {
                id: job_id,
                printer_handle,
                document_name: doc_name.to_string(),
                spool_data: Vec::new(),
                page_count: 0,
                status: PrintJobStatus::Spooling,
                started: std::time::Instant::now(),
            },
        );
        self.active_jobs.insert(job_id, printer_handle);
        Some(job_id)
    }

    pub fn end_doc_printer(&mut self, job_id: u32) -> bool {
        // Move the job out of the map instead of cloning its (up to 64 MiB)
        // spool buffer. The owned value is re-inserted below.
        let mut job = match self.jobs.remove(&job_id) {
            Some(job) => job,
            None => return false,
        };
        self.active_jobs.remove(&job_id);

        // EndDocPrinter is idempotent: the job is already finalized, so
        // return success without writing a second PDF over the first one.
        if job.status == PrintJobStatus::Completed {
            self.jobs.insert(job_id, job);
            self.evict_completed_jobs();
            return true;
        }

        job.status = PrintJobStatus::Completed;
        let pdf_data = self.generate_pdf(&job.document_name, job.page_count);
        let output_path = print_output_path(job_id, &job.document_name);
        match write_new_print_file(&output_path, &pdf_data) {
            Ok(path) => {
                if path != output_path {
                    // A numbered suffix was used because an earlier print of
                    // the same job/name already existed; never overwrite it.
                    crate::logging::log_rate_limited(
                        crate::logging::LogLevel::Info,
                        "print.output_suffix",
                        std::time::Duration::from_secs(60),
                        || format!("[print] retained earlier output; wrote {}", path.display()),
                    );
                }
            }
            Err(error) => crate::logging::log_rate_limited(
                crate::logging::LogLevel::Warn,
                "print.output_write",
                std::time::Duration::from_secs(60),
                || {
                    format!(
                        "[print] failed to save print output to {}: {}",
                        output_path.display(),
                        error
                    )
                },
            ),
        }

        self.jobs.insert(job_id, job);
        self.evict_completed_jobs();
        true
    }

    /// Bound the retained job history so completed jobs (and their spool
    /// data) cannot accumulate without limit. Active jobs are never evicted.
    fn evict_completed_jobs(&mut self) {
        while self.jobs.len() > MAX_RETAINED_JOBS {
            let oldest = self
                .jobs
                .keys()
                .filter(|id| !self.active_jobs.contains_key(id))
                .min()
                .copied();
            match oldest {
                Some(id) => {
                    self.jobs.remove(&id);
                }
                None => break,
            }
        }
    }

    /// Get the most recent active job ID for a printer handle (used by Win32
    /// dispatch, which keys EndPage/WritePrinter on the printer handle).
    pub fn active_job_for_printer(&self, printer_handle: PrinterHandle) -> Option<u32> {
        self.active_jobs
            .iter()
            .filter(|(_, owner)| **owner == printer_handle)
            .map(|(job_id, _)| *job_id)
            .max()
    }

    pub fn start_page_printer(&mut self, job_id: u32) -> bool {
        if let Some(job) = self.jobs.get_mut(&job_id) {
            job.page_count += 1;
            true
        } else {
            false
        }
    }

    pub fn end_page_printer(&mut self, _job_id: u32) -> bool {
        true
    }

    pub fn write_printer(&mut self, job_id: u32, data: &[u8]) -> bool {
        if let Some(job) = self.jobs.get_mut(&job_id) {
            if job.spool_data.len() < MAX_SPOOL_BYTES {
                let remaining = MAX_SPOOL_BYTES - job.spool_data.len();
                job.spool_data
                    .extend_from_slice(&data[..remaining.min(data.len())]);
            }
            true
        } else {
            false
        }
    }

    pub fn read_printer(&mut self, job_id: u32, _buf: &mut [u8]) -> Option<u32> {
        // ReadPrinter returns zero bytes for our virtual printer, but only
        // for a job this subsystem actually owns.
        if self.jobs.contains_key(&job_id) {
            Some(0)
        } else {
            None
        }
    }

    pub fn enum_printers(&self) -> Vec<&PrinterInfo> {
        self.printers.values().collect()
    }

    pub fn get_printer(&self, handle: PrinterHandle) -> Option<&PrinterInfo> {
        self.printers.get(&handle)
    }

    pub fn set_printer(&mut self, handle: PrinterHandle, info: PrinterInfo) -> bool {
        match self.printers.entry(handle) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.insert(info);
                true
            }
            _ => false,
        }
    }

    pub fn add_printer(&mut self, info: PrinterInfo) -> Option<PrinterHandle> {
        let handle = self.next_handle;
        self.next_handle += 1;
        self.printers.insert(handle, info);
        Some(handle)
    }

    pub fn delete_printer(&mut self, handle: PrinterHandle) -> bool {
        self.printers.remove(&handle).is_some()
    }

    // ── GDI Printer DC support ────────────────────────────────────────────

    /// Create a virtual printer DC that captures GDI calls
    pub fn create_printer_dc(&mut self, printer_name: &str) -> Option<PrinterDcHandle> {
        let handle = self.next_dc_handle;
        self.next_dc_handle += 1;
        self.printer_dcs.insert(
            handle,
            PrinterDc {
                handle,
                printer_name: printer_name.to_string(),
            },
        );
        Some(handle)
    }

    pub fn get_printer_dc(&self, dc_handle: PrinterDcHandle) -> Option<&PrinterDc> {
        self.printer_dcs.get(&dc_handle)
    }

    pub fn get_printer_dc_mut(&mut self, dc_handle: PrinterDcHandle) -> Option<&mut PrinterDc> {
        self.printer_dcs.get_mut(&dc_handle)
    }

    pub fn delete_printer_dc(&mut self, dc_handle: PrinterDcHandle) -> bool {
        self.printer_dcs.remove(&dc_handle).is_some()
    }

    // ── macOS Print Bridge ────────────────────────────────────────────────

    /// Show macOS print dialog for a PDF.
    ///
    /// The PDF is handed to the system opener (`open` → Preview). It must stay
    /// on disk while Preview reads it, so this function never deletes it
    /// synchronously; stale dialog PDFs are reaped by
    /// `cleanup_stale_temp_pdfs` on a later invocation. Any failure returns
    /// `false` (the previous implementation reported success on spawn error).
    pub fn show_print_dialog(pdf_data: &[u8]) -> bool {
        Self::show_print_dialog_with_opener(pdf_data, "open")
    }

    fn show_print_dialog_with_opener(pdf_data: &[u8], opener: &str) -> bool {
        // Write into a per-process temp dir and remove stale files so repeated
        // dialog invocations cannot accumulate unbounded temp PDFs.
        let temp_dir = std::env::temp_dir().join(format!("casa1_print_{}", std::process::id()));
        if let Err(e) = std::fs::create_dir_all(&temp_dir) {
            crate::logging::log_rate_limited(
                crate::logging::LogLevel::Warn,
                "print.dialog_temp_dir",
                std::time::Duration::from_secs(60),
                || {
                    format!(
                        "[print] failed to create temp dir {}: {e}",
                        temp_dir.display()
                    )
                },
            );
            return false;
        }
        cleanup_stale_temp_pdfs(&temp_dir);
        let temp_path = temp_dir.join(format!(
            "dialog_{}.pdf",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        if let Err(e) = std::fs::write(&temp_path, pdf_data) {
            crate::logging::log_rate_limited(
                crate::logging::LogLevel::Warn,
                "print.dialog_write",
                std::time::Duration::from_secs(60),
                || {
                    format!(
                        "[print] failed to write temp PDF {}: {e}",
                        temp_path.display()
                    )
                },
            );
            return false;
        }
        match std::process::Command::new(opener).arg(&temp_path).spawn() {
            Ok(mut child) => {
                // `open` returns immediately after handing the file to
                // Preview; waiting reaps it. Do NOT remove the PDF here:
                // Preview may not have read it yet.
                let _ = child.wait();
                true
            }
            Err(e) => {
                crate::logging::log_rate_limited(
                    crate::logging::LogLevel::Warn,
                    "print.dialog_open",
                    std::time::Duration::from_secs(60),
                    || {
                        format!(
                            "[print] failed to open PDF {} with system handler: {e}",
                            temp_path.display()
                        )
                    },
                );
                // No reader consumed this file, so it is safe to remove now.
                let _ = std::fs::remove_file(&temp_path);
                false
            }
        }
    }

    // ── PDF Generation ────────────────────────────────────────────────────

    /// Generate a simple PDF with proper multi-page support.
    ///
    /// Spool bytes are intentionally not embedded: the old debug hex dump
    /// (up to 8,192 characters) bloated every PDF and leaked guest payload
    /// bytes into a printable document.
    fn generate_pdf(&self, doc_name: &str, page_count: u32) -> Vec<u8> {
        let mut pdf = Vec::new();

        // PDF header
        pdf.extend_from_slice(b"%PDF-1.4\n");

        // Build PDF objects with the given page count
        let objects = self.build_pdf_objects(doc_name, page_count);
        let mut offsets: Vec<usize> = Vec::new();

        for (i, obj) in objects.iter().enumerate() {
            offsets.push(pdf.len());
            pdf.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            pdf.extend_from_slice(obj.as_bytes());
            pdf.extend_from_slice(b"\nendobj\n");
        }

        // Cross-reference table
        let xref_offset = pdf.len();
        pdf.extend_from_slice(b"xref\n");
        pdf.extend_from_slice(format!("0 {}\n", objects.len() + 1).as_bytes());
        pdf.extend_from_slice(b"0000000000 65535 f \n");
        for offset in &offsets {
            pdf.extend_from_slice(format!("{:010} 00000 n \n", offset).as_bytes());
        }

        // Trailer
        pdf.extend_from_slice(b"trailer\n");
        pdf.extend_from_slice(
            format!("<< /Size {} /Root 1 0 R >>\n", objects.len() + 1).as_bytes(),
        );
        pdf.extend_from_slice(b"startxref\n");
        pdf.extend_from_slice(format!("{}\n", xref_offset).as_bytes());
        pdf.extend_from_slice(b"%%EOF\n");

        pdf
    }

    /// Build PDF objects for multi-page document.
    ///
    /// Generates one page object per page (minimum 1) plus catalog, pages tree,
    /// content streams, and font resources. Each page shows a header with the
    /// document name and page number.
    fn build_pdf_objects(&self, doc_name: &str, page_count: u32) -> Vec<String> {
        // PDF literal strings are byte strings in the font encoding. Escape
        // the delimiters and fold anything non-ASCII to '?' so a guest-chosen
        // Unicode document name cannot produce a malformed PDF.
        let safe_name = pdf_literal_text(doc_name);
        let actual_pages = page_count.max(1) as usize;

        let mut objects: Vec<String> = Vec::new();

        // Object 1: Catalog
        objects.push(r"<< /Type /Catalog /Pages 2 0 R >>".to_string());

        // Object 2: Pages tree node
        let kids_refs: Vec<String> = (0..actual_pages)
            .map(|p| format!("{} 0 R", 3 + p * 2))
            .collect();
        objects.push(format!(
            r"<< /Type /Pages /Kids [{}] /Count {} >>",
            kids_refs.join(" "),
            actual_pages
        ));

        // Page objects live at 3 + 2*p and their content streams at 4 + 2*p;
        // the per-page font objects are appended after them at 3 + 2*pages + p.
        for page_num in 0..actual_pages {
            let content_obj_num = 4 + page_num * 2;
            let font_obj_num = 3 + actual_pages * 2 + page_num;

            // Page object
            objects.push(format!(
                r"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>",
                content_obj_num,
                font_obj_num,
            ));

            let page_label = if actual_pages == 1 {
                format!("Page {}", page_num + 1)
            } else {
                format!("Page {} of {}", page_num + 1, actual_pages)
            };

            // Build the content stream first so /Length matches its exact
            // byte count.
            let content = if page_num == 0 {
                // First page: document info only. The spool payload is never
                // rendered (removed 8,192-char hex dump).
                format!(
                    "BT /F1 12 Tf 100 700 Td (Printed from Casa1 - {}) Tj ET\n\
                     BT /F1 10 Tf 100 680 Td ({}) Tj ET",
                    safe_name, page_label,
                )
            } else {
                // Subsequent pages: just header and page number
                format!(
                    "BT /F1 12 Tf 100 700 Td (Printed from Casa1 - {}) Tj ET\n\
                     BT /F1 10 Tf 100 680 Td ({}) Tj ET",
                    safe_name, page_label,
                )
            };
            objects.push(format!(
                "<< /Length {} >> stream\n{}\nendstream",
                content.len(),
                content
            ));
        }

        // Add font resources (one font object per page shares the same definition)
        for _ in 0..actual_pages {
            objects.push(r"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string());
        }

        objects
    }
}

/// Info for the built-in "Microsoft Print to PDF" printer.
fn default_printer_info() -> PrinterInfo {
    PrinterInfo {
        name: "Microsoft Print to PDF".to_string(),
        port: "PORTPROMPT:".to_string(),
        driver: "Microsoft Print to PDF".to_string(),
        comment: "Print to PDF file".to_string(),
        location: "".to_string(),
        status: 0,       // PRINTER_STATUS_READY
        attributes: 0x4, // PRINTER_ATTRIBUTE_DIRECT
        jobs: 0,
        default_priority: 1,
    }
}

/// Reduce a guest-controlled document name to `[A-Za-z0-9_-]` so it can never
/// escape the output directory via `/`, `..` or other path metacharacters.
/// Non-ASCII characters (including CJK, emoji and combining marks) are folded
/// to `_`, so the resulting path is always a valid ASCII filename component.
fn sanitize_print_filename(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .take(64)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "document".to_string()
    } else {
        sanitized
    }
}

/// Escape a string for a PDF literal string and fold non-ASCII scalar values
/// to `?` (the built-in Helvetica/WinAnsi encoding cannot represent them).
fn pdf_literal_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for character in input.chars().take(256) {
        match character {
            '\\' => out.push_str("\\\\"),
            '(' => out.push_str("\\("),
            ')' => out.push_str("\\)"),
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            _ => out.push('?'),
        }
    }
    out
}

/// Generated print PDFs live under the OS temp directory — never the process
/// CWD and never the invoking user's real `~/Documents`.
fn print_output_path(job_id: u32, document_name: &str) -> PathBuf {
    std::env::temp_dir().join(PRINT_OUTPUT_DIR).join(format!(
        "print_{}_{}.pdf",
        job_id,
        sanitize_print_filename(document_name)
    ))
}

/// Create a brand-new PDF file, adding a numbered suffix when an earlier print
/// already occupies the preferred name. `create_new` makes the no-overwrite
/// guarantee atomic even if another printer thread races us.
fn write_new_print_file(preferred: &Path, pdf_data: &[u8]) -> std::io::Result<PathBuf> {
    write_new_print_file_bounded(preferred, pdf_data, u32::MAX)
}

/// Same as [`write_new_print_file`] with an explicit suffix budget so the
/// exhaustion error stays reachable in adversarial tests; production callers
/// pass `u32::MAX` (the historical search space).
fn write_new_print_file_bounded(
    preferred: &Path,
    pdf_data: &[u8],
    suffix_budget: u32,
) -> std::io::Result<PathBuf> {
    if let Some(parent) = preferred.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let stem = preferred
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "print".to_string());
    let mut candidate = preferred.to_path_buf();
    for suffix in 0..suffix_budget {
        if suffix > 0 {
            candidate = preferred.with_file_name(format!("{stem}_{suffix}.pdf"));
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                let write_result = file.write_all(pdf_data).and_then(|_| file.sync_all());
                if let Err(error) = write_result {
                    let _ = std::fs::remove_file(&candidate);
                    return Err(error);
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::other("no free numbered print filename"))
}

/// Remove dialog temp PDFs older than one hour.
fn cleanup_stale_temp_pdfs(temp_dir: &std::path::Path) {
    let now = std::time::SystemTime::now();
    if let Ok(entries) = std::fs::read_dir(temp_dir) {
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            if now
                .duration_since(modified)
                .is_ok_and(|age| age.as_secs() > 3600)
            {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

impl Default for PrintSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn print_outputs_for(job_id: u32, document_name: &str) -> Vec<PathBuf> {
        let dir = std::env::temp_dir().join(PRINT_OUTPUT_DIR);
        let prefix = format!("print_{job_id}_{}", sanitize_print_filename(document_name));
        let mut paths = match std::fs::read_dir(&dir) {
            Ok(entries) => entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().starts_with(&prefix))
                        .unwrap_or(false)
                })
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        };
        paths.sort();
        paths
    }

    fn cleanup_outputs(job_id: u32, document_name: &str) {
        for path in print_outputs_for(job_id, document_name) {
            let _ = std::fs::remove_file(path);
        }
    }

    fn second_printer(name: &str) -> PrinterInfo {
        PrinterInfo {
            name: name.to_string(),
            port: "FILE:".to_string(),
            driver: "Casa1 Virtual".to_string(),
            comment: String::new(),
            location: String::new(),
            status: 0,
            attributes: 0,
            jobs: 0,
            default_priority: 1,
        }
    }

    /// Serializes every test that touches the shared `casa1-prints` output
    /// directory: one adversarial test swaps the directory for a plain file
    /// (and another makes it read-only), which must never race a concurrent
    /// lifecycle test.
    static OUTPUT_DIR_LOCK: Mutex<()> = Mutex::new(());

    fn output_dir_guard() -> std::sync::MutexGuard<'static, ()> {
        OUTPUT_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Serializes the dialog tests: they all share the per-process
    /// `casa1_print_<pid>` temp directory, and two of them replace it with a
    /// blocker file / a read-only directory.
    static DIALOG_DIR_LOCK: Mutex<()> = Mutex::new(());

    fn dialog_dir_guard() -> std::sync::MutexGuard<'static, ()> {
        DIALOG_DIR_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn dialog_dir() -> PathBuf {
        std::env::temp_dir().join(format!("casa1_print_{}", std::process::id()))
    }

    #[test]
    fn test_enum_printers() {
        let ps = PrintSubsystem::new();
        let printers = ps.enum_printers();
        assert!(!printers.is_empty(), "Should have at least 1 printer");
        assert_eq!(printers.len(), 1);
        assert_eq!(printers[0].name, "Microsoft Print to PDF");
    }

    #[test]
    fn test_set_printer() {
        let mut ps = PrintSubsystem::new();
        assert!(ps.set_printer(
            1,
            PrinterInfo {
                name: "Updated Printer".to_string(),
                port: "LPT1:".to_string(),
                driver: "Updated".to_string(),
                comment: "Updated comment".to_string(),
                location: "Lab".to_string(),
                status: 0,
                attributes: 0,
                jobs: 0,
                default_priority: 1,
            }
        ));

        let printer = ps.get_printer(1).unwrap();
        assert_eq!(printer.name, "Updated Printer");

        // Set non-existent printer
        assert!(!ps.set_printer(
            999,
            PrinterInfo {
                name: "Ghost".to_string(),
                port: "".to_string(),
                driver: "".to_string(),
                comment: "".to_string(),
                location: "".to_string(),
                status: 0,
                attributes: 0,
                jobs: 0,
                default_priority: 1,
            }
        ));
    }

    #[test]
    fn test_job_lifecycle_complete() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).unwrap();

        // Full lifecycle: open → start doc → pages → write → end doc
        let job_id = ps.start_doc_printer(handle, "LifecycleTest").unwrap();

        assert!(ps.start_page_printer(job_id));
        assert!(ps.write_printer(job_id, b"Page 1 content"));
        assert!(ps.end_page_printer(job_id));

        assert!(ps.start_page_printer(job_id));
        assert!(ps.write_printer(job_id, b"Page 2 content"));
        assert!(ps.end_page_printer(job_id));

        assert!(ps.end_doc_printer(job_id));

        let job = ps.jobs.get(&job_id).unwrap();
        assert_eq!(job.status, PrintJobStatus::Completed);
        assert_eq!(job.page_count, 2);
        assert!(!job.spool_data.is_empty());
    }

    // -----------------------------------------------------------------------
    //  Item 241: Print spool lifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_end_doc_printer_finalizes_status() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();

        let handle = ps.open_printer(None).expect("should open printer");

        let job_id = ps
            .start_doc_printer(handle, "finalize_test")
            .expect("should start document");

        assert!(ps.start_page_printer(job_id), "should start page");
        assert!(ps.write_printer(job_id, b"test data"), "should write data");
        assert!(ps.end_page_printer(job_id), "should end page");

        // End document - status should become Completed
        assert!(ps.end_doc_printer(job_id), "should end document");

        // Verify the job status is Completed
        let job = ps.jobs.get(&job_id).expect("job should still exist");
        assert_eq!(
            job.status,
            PrintJobStatus::Completed,
            "job status should be Completed"
        );
        assert_eq!(job.page_count, 1, "should have 1 page");
        assert!(!job.spool_data.is_empty(), "spool data should not be empty");

        assert!(ps.close_printer(handle), "should close printer");
    }

    #[test]
    fn test_printer_handle_rejects_operations_after_close() {
        let mut ps = PrintSubsystem::new();

        let handle = ps.open_printer(None).expect("should open printer");
        assert!(ps.close_printer(handle), "should close printer");

        // After close, start_doc_printer with the old handle should still work
        // (since the handle is just a number, not tracked for validity)
        // But the printer is removed from the printers map
        assert!(ps.close_printer(handle), "double close should succeed");
    }

    #[test]
    fn test_job_lifecycle_start_end_page_without_write() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();

        let handle = ps.open_printer(None).expect("should open printer");

        let job_id = ps
            .start_doc_printer(handle, "empty_page_doc")
            .expect("should start document");

        // Start and end a page without writing any data
        assert!(ps.start_page_printer(job_id), "should start empty page");
        assert!(ps.end_page_printer(job_id), "should end empty page");

        // Write data on a second page
        assert!(ps.start_page_printer(job_id), "should start second page");
        assert!(
            ps.write_printer(job_id, b"data on second page"),
            "should write data"
        );
        assert!(ps.end_page_printer(job_id), "should end second page");

        assert!(ps.end_doc_printer(job_id), "should end document");

        // Verify job details
        let job = ps.jobs.get(&job_id).expect("job should exist");
        assert_eq!(job.status, PrintJobStatus::Completed);
        assert_eq!(job.page_count, 2, "should have 2 pages");
        assert!(!job.spool_data.is_empty(), "should have spool data");

        assert!(ps.close_printer(handle), "should close printer");
    }

    // ── Adversarial regression tests for the print findings ──────────────

    #[test]
    fn unknown_printer_handle_is_rejected_by_close_and_doc_start() {
        let mut ps = PrintSubsystem::new();
        assert!(
            !ps.close_printer(0xDEAD_BEEF),
            "unknown handle must return FALSE"
        );
        assert!(
            ps.start_doc_printer(0xDEAD_BEEF, "ghost").is_none(),
            "unknown printer must not accept a document"
        );
        assert_eq!(ps.read_printer(0xDEAD_BEEF, &mut [0u8; 4]), None);
    }

    #[test]
    fn closing_one_printer_keeps_another_printers_active_job() {
        let mut ps = PrintSubsystem::new();
        let first = ps.open_printer(None).expect("default printer");
        let second = ps
            .add_printer(second_printer("Second"))
            .expect("second printer");
        let first_job = ps.start_doc_printer(first, "first").expect("first job");
        let second_job = ps.start_doc_printer(second, "second").expect("second job");

        assert!(ps.close_printer(first));
        assert!(!ps.jobs.contains_key(&first_job));
        assert!(ps.jobs.contains_key(&second_job), "other job was cancelled");
        assert_eq!(ps.active_job_for_printer(second), Some(second_job));
        assert_eq!(ps.active_job_for_printer(first), None);

        assert!(ps.close_printer(second));
    }

    #[test]
    fn ending_one_of_two_jobs_leaves_the_other_active() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        let older = ps.start_doc_printer(handle, "older").expect("older job");
        let newer = ps.start_doc_printer(handle, "newer").expect("newer job");

        assert!(ps.end_doc_printer(older));
        assert!(!ps.active_jobs.contains_key(&older));
        assert!(
            ps.active_jobs.contains_key(&newer),
            "newer job was cancelled"
        );
        assert_eq!(ps.active_job_for_printer(handle), Some(newer));
        assert!(ps.jobs.contains_key(&older));
        assert!(ps.close_printer(handle));
        cleanup_outputs(older, "older");
        cleanup_outputs(newer, "newer");
    }

    #[test]
    fn end_doc_rejects_duplicate_pdf_and_is_idempotent() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        let job = ps.start_doc_printer(handle, "idempotent_doc").expect("job");
        assert!(ps.start_page_printer(job));
        assert!(ps.write_printer(job, b"payload"));
        let before = print_outputs_for(job, "idempotent_doc").len();
        assert!(ps.end_doc_printer(job));
        let after_first = print_outputs_for(job, "idempotent_doc").len();
        assert_eq!(after_first, before + 1, "first EndDoc writes one PDF");

        assert!(
            ps.end_doc_printer(job),
            "second EndDoc must still return TRUE"
        );
        assert_eq!(
            print_outputs_for(job, "idempotent_doc").len(),
            after_first,
            "second EndDoc must not write another PDF"
        );
        assert!(ps.close_printer(handle));
        cleanup_outputs(job, "idempotent_doc");
    }

    #[test]
    fn write_new_print_file_rejects_overwrite_with_numbered_suffix() {
        let _output_guard = output_dir_guard();
        let base = std::env::temp_dir()
            .join(PRINT_OUTPUT_DIR)
            .join(format!("casa1_suffix_test_{}", std::process::id()));
        std::fs::create_dir_all(base.parent().expect("parent")).expect("dir");
        let preferred = base.with_extension("pdf");
        let first = write_new_print_file(&preferred, b"first").expect("first write");
        let second = write_new_print_file(&preferred, b"second").expect("second write");
        assert_ne!(first, second, "earlier print must not be overwritten");
        assert_eq!(std::fs::read(&first).expect("read first"), b"first");
        assert_eq!(std::fs::read(&second).expect("read second"), b"second");

        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }

    #[test]
    fn spool_cap_drops_bytes_past_64_mib_and_never_grows_the_buffer() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        let job = ps.start_doc_printer(handle, "spool_cap").expect("job");
        let chunk = vec![0xABu8; 1024 * 1024];
        for _ in 0..(MAX_SPOOL_BYTES / chunk.len() + 2) {
            assert!(ps.write_printer(job, &chunk));
        }
        let retained = ps.jobs.get(&job).expect("job").spool_data.len();
        assert_eq!(retained, MAX_SPOOL_BYTES, "spool must be capped exactly");
        assert!(ps.close_printer(handle));
    }

    #[test]
    fn completed_job_retention_is_bounded_and_never_evicts_active_jobs() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        for _ in 0..40 {
            let job = ps.start_doc_printer(handle, "retained").expect("job");
            assert!(ps.start_page_printer(job));
            assert!(ps.write_printer(job, b"x"));
            assert!(ps.end_doc_printer(job));
            assert!(
                ps.jobs.len() <= MAX_RETAINED_JOBS,
                "retained jobs must stay bounded"
            );
            cleanup_outputs(job, "retained");
        }
        assert_eq!(ps.jobs.len(), MAX_RETAINED_JOBS);

        let active = ps.start_doc_printer(handle, "active").expect("active job");
        for _ in 0..4 {
            let job = ps.start_doc_printer(handle, "churn").expect("job");
            assert!(ps.write_printer(job, b"x"));
            assert!(ps.end_doc_printer(job));
            assert!(ps.jobs.contains_key(&active), "active job was evicted");
            assert!(ps.active_jobs.contains_key(&active));
            cleanup_outputs(job, "churn");
        }
        assert!(ps.jobs.len() <= MAX_RETAINED_JOBS);
        assert!(ps.close_printer(handle));
        cleanup_outputs(active, "active");
    }

    #[test]
    fn generated_pdf_rejects_spool_hex_dump_and_non_ascii_names() {
        let ps = PrintSubsystem::new();
        let pdf = ps.generate_pdf("日本語 (tëst)", 1);
        assert_eq!(
            pdf.iter().all(|byte| byte.is_ascii()),
            true,
            "PDF must stay ASCII even for a non-ASCII document name"
        );
        let text = String::from_utf8(pdf).expect("ascii pdf");
        assert_eq!(
            text.contains("Spool data:"),
            false,
            "the debug hex dump must be gone"
        );
        assert_eq!(text.contains("Printed from Casa1 - ??? \\(t?st\\)"), true);

        // Backslashes and parens are the PDF literal-string escape set: a
        // guest document name containing them must be escaped, never emitted
        // raw into the content stream.
        let escaped_pdf = ps.generate_pdf("a\\b(c)", 1);
        let escaped_text = String::from_utf8(escaped_pdf).expect("ascii pdf");
        assert_eq!(
            escaped_text.contains("a\\\\b\\(c\\)"),
            true,
            "backslashes and parens must be PDF-escaped"
        );
    }

    #[test]
    fn sanitized_print_filename_is_ascii_and_cannot_escape_the_directory() {
        let sanitized = sanitize_print_filename("../../日本語 (tëst)");
        assert!(sanitized.is_ascii());
        assert!(!sanitized.contains('/'));
        assert!(!sanitized.contains('\\'));
        assert!(!sanitized.contains(".."));
        let path = print_output_path(7, "../../日本語");
        assert!(
            path.starts_with(std::env::temp_dir()),
            "prints must live in the temp directory"
        );
        assert!(!path.to_string_lossy().contains("Documents"));
        assert_eq!(
            path.parent()
                .and_then(Path::file_name)
                .and_then(|v| v.to_str()),
            Some(PRINT_OUTPUT_DIR)
        );
    }

    #[test]
    fn show_print_dialog_rejects_an_opener_that_cannot_run() {
        let _dialog_guard = dialog_dir_guard();
        assert_eq!(
            PrintSubsystem::show_print_dialog_with_opener(
                b"%PDF-1.4\n",
                "/nonexistent/casa1-print-opener"
            ),
            false,
            "a failed spawn must report FALSE"
        );
        let _ = std::fs::remove_dir_all(dialog_dir());
    }

    #[test]
    fn show_print_dialog_avoids_preview_race_by_keeping_the_pdf() {
        let _dialog_guard = dialog_dir_guard();
        assert_eq!(
            PrintSubsystem::show_print_dialog_with_opener(b"%PDF-1.4\n", "/usr/bin/true"),
            true,
            "opener success must report TRUE"
        );
        let dir = dialog_dir();
        let newest = std::fs::read_dir(&dir)
            .expect("dialog temp dir")
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "pdf"))
            .max()
            .expect("dialog PDF must remain for the reader");
        assert_eq!(
            newest.exists(),
            true,
            "PDF was deleted before Preview could read it"
        );
        let _ = std::fs::remove_file(newest);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn end_doc_printer_rejects_a_job_this_subsystem_never_issued() {
        let mut ps = PrintSubsystem::new();
        assert_eq!(
            ps.end_doc_printer(0xDEAD_BEEF),
            false,
            "EndDocPrinter of an unknown job must return FALSE"
        );
    }

    #[test]
    fn end_doc_output_write_failure_still_finalizes_the_job() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        let job = ps.start_doc_printer(handle, "blocked_dir").expect("job");
        assert!(ps.start_page_printer(job));
        assert!(ps.write_printer(job, b"payload"));
        let dir = std::env::temp_dir().join(PRINT_OUTPUT_DIR);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::write(&dir, b"file blocks the print output directory").expect("blocker file");
        assert_eq!(
            ps.end_doc_printer(job),
            true,
            "a failed save must not fail the document"
        );
        assert_eq!(
            ps.jobs.get(&job).expect("job").status,
            PrintJobStatus::Completed
        );
        assert_eq!(
            print_outputs_for(job, "blocked_dir").len(),
            0,
            "no PDF may exist under a blocked output directory"
        );
        let _ = std::fs::remove_file(&dir);
        assert!(ps.close_printer(handle));
    }

    #[test]
    fn end_doc_duplicate_output_is_never_overwritten_and_writes_a_numbered_copy() {
        let _output_guard = output_dir_guard();
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        let job = ps.start_doc_printer(handle, "suffix_retain").expect("job");
        assert!(ps.start_page_printer(job));
        assert!(ps.write_printer(job, b"payload"));
        // Occupy the preferred output name so EndDoc must take the numbered
        // suffix path instead of overwriting the earlier print.
        let preferred = print_output_path(job, "suffix_retain");
        std::fs::create_dir_all(preferred.parent().expect("output dir")).expect("dir");
        std::fs::write(&preferred, b"earlier print").expect("occupy preferred");
        assert_eq!(
            ps.end_doc_printer(job),
            true,
            "the suffixed write must still complete the document"
        );
        assert_eq!(
            std::fs::read(&preferred).expect("earlier output"),
            b"earlier print",
            "the earlier print must be retained byte-for-byte"
        );
        let suffixed = preferred
            .parent()
            .expect("output dir")
            .join(format!("print_{job}_suffix_retain_1.pdf"));
        assert_eq!(
            suffixed.is_file(),
            true,
            "the numbered copy must exist next to the retained output"
        );
        cleanup_outputs(job, "suffix_retain");
        assert!(ps.close_printer(handle));
    }

    #[test]
    fn eviction_never_drops_active_jobs_when_every_retained_slot_is_active() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        for _ in 0..=MAX_RETAINED_JOBS {
            ps.start_doc_printer(handle, "active_only").expect("job");
        }
        assert_eq!(ps.jobs.len(), MAX_RETAINED_JOBS + 1);
        assert_eq!(ps.active_jobs.len(), MAX_RETAINED_JOBS + 1);
        ps.evict_completed_jobs();
        assert_eq!(
            ps.jobs.len(),
            MAX_RETAINED_JOBS + 1,
            "active jobs must never be evicted"
        );
        assert!(ps.close_printer(handle));
        assert_eq!(ps.jobs.len(), 0, "closing the printer cancels its jobs");
    }

    #[test]
    fn read_printer_rejects_unknown_jobs_and_returns_zero_for_owned_ones() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("printer");
        let job = ps.start_doc_printer(handle, "readback").expect("job");
        assert_eq!(
            ps.read_printer(job, &mut [0u8; 8]),
            Some(0),
            "an owned job reads zero bytes"
        );
        assert_eq!(
            ps.read_printer(job + 10_000, &mut [0u8; 8]),
            None,
            "an unknown job must be rejected"
        );
        assert!(ps.close_printer(handle));
    }

    #[test]
    fn show_print_dialog_rejects_a_temp_dir_occupied_by_a_file() {
        let _dialog_guard = dialog_dir_guard();
        let dir = dialog_dir();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::write(&dir, b"not a directory").expect("blocker file");
        assert_eq!(
            PrintSubsystem::show_print_dialog_with_opener(b"%PDF-1.4\n", "/usr/bin/true"),
            false,
            "a temp-dir creation failure must report FALSE"
        );
        assert_eq!(
            std::fs::remove_file(&dir).is_ok(),
            true,
            "the blocker file must be the only artifact left behind"
        );
    }

    #[test]
    fn show_print_dialog_reports_false_when_the_temp_pdf_write_fails() {
        use std::os::unix::fs::PermissionsExt;
        let _dialog_guard = dialog_dir_guard();
        let dir = dialog_dir();
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dialog dir");
        let mut permissions = std::fs::metadata(&dir).expect("metadata").permissions();
        permissions.set_mode(0o555);
        std::fs::set_permissions(&dir, permissions.clone()).expect("make the dialog dir read-only");
        assert_eq!(
            PrintSubsystem::show_print_dialog_with_opener(b"%PDF-1.4\n", "/usr/bin/true"),
            false,
            "a temp PDF write failure must report FALSE"
        );
        permissions.set_mode(0o755);
        std::fs::set_permissions(&dir, permissions).expect("restore the dialog dir");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_new_print_file_on_a_parentless_path_fails_with_enoent() {
        let error = write_new_print_file(Path::new(""), b"payload")
            .expect_err("an empty preferred path cannot be created");
        assert_eq!(
            error.raw_os_error(),
            Some(2),
            "the pinned failure is ENOENT from the empty path"
        );
    }

    #[test]
    fn write_new_print_file_removes_the_partial_file_when_the_write_fails() {
        const CHILD_ENV: &str = "CASA1_PRINT_RLIMIT_CHILD_DIR";
        if let Ok(dir) = std::env::var(CHILD_ENV) {
            let mut original: libc::rlimit = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut original) },
                0
            );
            let mut limited = original;
            limited.rlim_cur = 256;
            let _ = unsafe { libc::signal(libc::SIGXFSZ, libc::SIG_IGN) };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limited) }, 0);
            let preferred = std::path::Path::new(&dir).join("rlimit.pdf");
            let error = write_new_print_file(&preferred, &[0xAB; 4096])
                .expect_err("exceeding RLIMIT_FSIZE must fail the save");
            assert_eq!(
                error.raw_os_error(),
                Some(libc::EFBIG),
                "the pinned write failure is EFBIG"
            );
            assert_eq!(
                preferred.exists(),
                false,
                "the partial file must be removed after the failed write"
            );
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &original) },
                0,
                "the child must restore the file-size limit before exit"
            );
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "casa1_print_rlimit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let status = std::process::Command::new(std::env::current_exe().expect("current exe"))
            .arg("--exact")
            .arg("print::tests::write_new_print_file_removes_the_partial_file_when_the_write_fails")
            .arg("--nocapture")
            .env(CHILD_ENV, &dir)
            .status()
            .expect("spawn the RLIMIT_FSIZE child");
        assert_eq!(
            status.success(),
            true,
            "the EFBIG child must complete the pinned failure path"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_new_print_file_exhausts_its_suffix_budget_and_reports_the_exact_error() {
        let dir = std::env::temp_dir().join(format!(
            "casa1_print_budget_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let preferred = dir.join("occupied.pdf");
        std::fs::create_dir_all(&preferred).expect("occupy the preferred name");
        let error = write_new_print_file_bounded(&preferred, b"payload", 1)
            .expect_err("a one-suffix budget must be exhausted by the occupant");
        assert_eq!(error.to_string(), "no free numbered print filename");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn show_print_dialog_via_system_open_never_deletes_the_stale_dialog_pdf() {
        const CHILD_ENV: &str = "CASA1_FAKE_OPEN_DIR";
        if let Ok(dir) = std::env::var(CHILD_ENV) {
            assert_eq!(
                PrintSubsystem::show_print_dialog(b"%PDF-1.4\n"),
                true,
                "the system-opener wrapper must report TRUE on success"
            );
            assert_eq!(
                std::path::Path::new(&dir).join("marker").exists(),
                true,
                "the fake `open` resolved from PATH must have been executed"
            );
            let _ = std::fs::remove_dir_all(dialog_dir());
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "casa1_fake_open_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let fake_open = dir.join("open");
        std::fs::write(
            &fake_open,
            "#!/bin/sh\n: > \"$CASA1_FAKE_OPEN_DIR/marker\"\nexit 0\n",
        )
        .expect("fake open");
        let mut permissions = std::fs::metadata(&fake_open)
            .expect("metadata")
            .permissions();
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake_open, permissions).expect("chmod fake open");
        let path_var = std::env::var("PATH").unwrap_or_default();
        let status = std::process::Command::new(std::env::current_exe().expect("current exe"))
            .arg("--exact")
            .arg("print::tests::show_print_dialog_via_system_open_never_deletes_the_stale_dialog_pdf")
            .arg("--nocapture")
            .env(CHILD_ENV, &dir)
            .env("PATH", format!("{}:{}", dir.display(), path_var))
            .status()
            .expect("spawn the system-opener child");
        assert_eq!(
            status.success(),
            true,
            "the system-opener child must complete the pinned path"
        );
        assert_eq!(
            dir.join("marker").exists(),
            true,
            "the child must have invoked the fake system `open`"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

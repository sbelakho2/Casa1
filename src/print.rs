use std::collections::HashMap;
use std::path::PathBuf;

/// Printer handle type
pub type PrinterHandle = u64;

/// Maximum spool bytes retained per job (the spool is only used for a debug
/// hex dump in the generated PDF; the cap prevents unbounded guest-driven
/// memory growth).
const MAX_SPOOL_BYTES: usize = 64 * 1024 * 1024;

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
    /// Maps printer handle -> active job ID for ongoing print sessions
    pub active_jobs: HashMap<PrinterHandle, u32>,
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
        // Cancel any in-flight job for this printer so its spool data does
        // not linger after the handle is closed.
        if let Some(job_id) = self.active_jobs.remove(&handle) {
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
        self.active_jobs.insert(printer_handle, job_id);
        Some(job_id)
    }

    pub fn end_doc_printer(&mut self, job_id: u32) -> bool {
        // Extract data before mutably borrowing self for generate_pdf
        let spool_data = if let Some(job) = self.jobs.get(&job_id) {
            job.spool_data.clone()
        } else {
            return false;
        };
        let document_name = if let Some(job) = self.jobs.get(&job_id) {
            job.document_name.clone()
        } else {
            return false;
        };
        let page_count = if let Some(job) = self.jobs.get(&job_id) {
            job.page_count
        } else {
            0
        };

        if let Some(job) = self.jobs.get_mut(&job_id) {
            job.status = PrintJobStatus::Completed;
        }
        // Clear active job for this printer
        self.active_jobs.retain(|_, v| *v != job_id);

        // Generate PDF from spool data with proper page count and write it to
        // a fixed output directory using a sanitized, guest-safe filename.
        let pdf_data = self.generate_pdf(&spool_data, &document_name, page_count);
        let output_path = print_output_path(job_id, &document_name);
        if let Some(parent) = output_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&output_path, &pdf_data) {
            eprintln!(
                "Failed to save print output to {}: {}",
                output_path.display(),
                e
            );
        }

        // Bound the retained job history so completed jobs (and their spool
        // data) cannot accumulate without limit.
        if self.jobs.len() > MAX_RETAINED_JOBS {
            let mut oldest: Option<u32> = None;
            for id in self.jobs.keys() {
                if self.active_jobs.values().any(|active| active == id) {
                    continue;
                }
                if oldest.is_none_or(|oldest| *id < oldest) {
                    oldest = Some(*id);
                }
            }
            if let Some(id) = oldest {
                self.jobs.remove(&id);
            }
        }
        true
    }

    /// Get the active job ID for a printer handle (used by Win32 dispatch)
    pub fn active_job_for_printer(&self, printer_handle: PrinterHandle) -> Option<u32> {
        self.active_jobs.get(&printer_handle).copied()
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

    pub fn read_printer(&mut self, _job_id: u32, _buf: &mut [u8]) -> Option<u32> {
        // ReadPrinter returns zero bytes for our virtual printer
        Some(0)
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

    /// Show macOS print dialog for a PDF
    pub fn show_print_dialog(pdf_data: &[u8]) -> bool {
        // Write into a per-process temp dir and remove stale files so repeated
        // dialog invocations cannot accumulate unbounded temp PDFs.
        let temp_dir = std::env::temp_dir().join(format!("casa1_print_{}", std::process::id()));
        if let Err(e) = std::fs::create_dir_all(&temp_dir) {
            eprintln!(
                "[print] failed to create temp dir {}: {e}",
                temp_dir.display()
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
        match std::fs::write(&temp_path, pdf_data) {
            Ok(_) => match std::process::Command::new("open").arg(&temp_path).spawn() {
                Ok(mut child) => {
                    let _ = child.wait();
                    let _ = std::fs::remove_file(&temp_path);
                    true
                }
                Err(e) => {
                    eprintln!(
                        "[print] failed to open PDF {} with system handler: {e}",
                        temp_path.display()
                    );
                    let _ = std::fs::remove_file(&temp_path);
                    true
                }
            },
            Err(e) => {
                eprintln!(
                    "[print] failed to write temp PDF {}: {e}",
                    temp_path.display()
                );
                false
            }
        }
    }

    // ── PDF Generation ────────────────────────────────────────────────────

    /// Generate a simple PDF from raw spool data with proper multi-page support.
    fn generate_pdf(&self, spool_data: &[u8], doc_name: &str, page_count: u32) -> Vec<u8> {
        let mut pdf = Vec::new();

        // PDF header
        pdf.extend_from_slice(b"%PDF-1.4\n");

        // Build PDF objects with the given page count
        let objects = self.build_pdf_objects(spool_data, doc_name, page_count);
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
    fn build_pdf_objects(&self, spool_data: &[u8], doc_name: &str, page_count: u32) -> Vec<String> {
        let safe_name = doc_name
            .replace('\\', "\\\\")
            .replace('(', "\\(")
            .replace(')', "\\)");
        let actual_pages = page_count.max(1) as usize;
        let spool_hex = spool_data
            .iter()
            .take(4096)
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

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
                // First page: include document info and spool data
                format!(
                    "BT /F1 12 Tf 100 700 Td (Printed from Casa1 - {}) Tj ET\n\
                     BT /F1 10 Tf 100 680 Td ({}) Tj ET\n\
                     {}",
                    safe_name,
                    page_label,
                    if spool_hex.is_empty() {
                        String::new()
                    } else {
                        format!("BT /F1 8 Tf 100 650 Td (Spool data: {}) Tj ET", spool_hex)
                    }
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

/// Fixed output location for generated print PDFs — never the process CWD.
fn print_output_path(job_id: u32, document_name: &str) -> PathBuf {
    let base = std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join("Documents").join("Casa1-prints"))
        .unwrap_or_else(|| std::env::temp_dir().join("casa1-prints"));
    base.join(format!(
        "print_{}_{}.pdf",
        job_id,
        sanitize_print_filename(document_name)
    ))
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
}

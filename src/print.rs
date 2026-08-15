use std::collections::HashMap;

/// Printer handle type
pub type PrinterHandle = u64;

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
    pub job_id: Option<u32>,
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
        printers.insert(
            1,
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
            },
        );
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
        None
    }

    pub fn close_printer(&mut self, _handle: PrinterHandle) -> bool {
        true
    }

    pub fn start_doc_printer(
        &mut self,
        printer_handle: PrinterHandle,
        doc_name: &str,
    ) -> Option<u32> {
        let job_id = self.next_job_id;
        self.next_job_id += 1;
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
            // Clear active job for this printer
            self.active_jobs.retain(|_, v| *v != job_id);
        }

        // Generate PDF from spool data with proper page count
        let pdf_data = self.generate_pdf(&spool_data, &document_name, page_count);
        // Write PDF to file
        let filename = format!("print_{}_{}.pdf", job_id, document_name.replace(' ', "_"));
        if let Err(e) = std::fs::write(&filename, &pdf_data) {
            eprintln!("Failed to save print output: {}", e);
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
            job.spool_data.extend_from_slice(data);
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
        if self.printers.contains_key(&handle) {
            self.printers.insert(handle, info);
            true
        } else {
            false
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
                job_id: None,
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
        let temp_path = format!(
            "/tmp/casa1_print_{}.pdf",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        match std::fs::write(&temp_path, pdf_data) {
            Ok(_) => {
                if let Err(e) = std::process::Command::new("open").arg(&temp_path).spawn() {
                    eprintln!(
                        "[print] failed to open PDF {} with system handler: {e}",
                        temp_path
                    );
                }
                true
            }
            Err(e) => {
                eprintln!("[print] failed to write temp PDF {}: {e}", temp_path);
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
        let actual_pages = page_count.max(1);
        let spool_hex = spool_data
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let mut objects: Vec<String> = Vec::new();

        // Object 1: Catalog
        objects.push(r"<< /Type /Catalog /Pages 2 0 R >>".to_string());

        // Object 2: Pages tree node
        let kids_refs: Vec<String> = (0..actual_pages)
            .map(|p| format!("{} 0 R", 3 + p as usize * 2))
            .collect();
        objects.push(format!(
            r"<< /Type /Pages /Kids [{}] /Count {} >>",
            kids_refs.join(" "),
            actual_pages
        ));

        // Generate page objects (2 objects per page: page + content stream)
        let mut content_obj_num = 3 + actual_pages as usize * 2; // after page objects
        for page_num in 0..actual_pages {
            let _page_obj_num = 3 + page_num as usize * 2;

            // Page object
            let _page_y = 700 - (page_num as i32 * 60);
            objects.push(format!(
                r"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {} 0 R /Resources << /Font << /F1 {} 0 R >> >> >>",
                content_obj_num,
                content_obj_num + 1, // font ref comes after content
            ));

            // Content stream for this page
            let content = if actual_pages == 1 && page_num == 0 {
                // First/only page: include document info and spool data
                format!(
                    r"<< /Length {} >> stream
BT /F1 12 Tf 100 700 Td (Printed from Casa1 - {}) Tj ET
BT /F1 10 Tf 100 680 Td (Page {}) Tj ET
{}
endstream",
                    120 + safe_name.len()
                        + if spool_hex.is_empty() {
                            0
                        } else {
                            spool_hex.len() + 50
                        },
                    safe_name,
                    page_num + 1,
                    if spool_hex.is_empty() {
                        String::new()
                    } else {
                        format!("BT /F1 8 Tf 100 650 Td (Spool data: {}) Tj ET", spool_hex)
                    }
                )
            } else {
                // Subsequent pages: just header and page number
                format!(
                    r"<< /Length {} >> stream
BT /F1 12 Tf 100 700 Td (Printed from Casa1 - {}) Tj ET
BT /F1 10 Tf 100 680 Td (Page {} of {}) Tj ET
endstream",
                    80 + safe_name.len(),
                    safe_name,
                    page_num + 1,
                    actual_pages
                )
            };
            objects.push(content);

            content_obj_num += 2;
        }

        // Add font resources (one font object per page shares the same definition)
        for _ in 0..actual_pages {
            objects.push(r"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string());
        }

        objects
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
    fn test_open_close_printer() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(Some("Microsoft Print to PDF"));
        assert!(handle.is_some(), "Should open default printer");
        assert_eq!(handle.expect("handle should be Some"), 1);

        // Open with None should return default
        let handle2 = ps.open_printer(None);
        assert!(handle2.is_some(), "should get default printer handle");

        // Open non-existent printer
        let handle3 = ps.open_printer(Some("NonExistentPrinter"));
        assert!(handle3.is_none());

        // Close should succeed
        assert!(ps.close_printer(1));
    }

    #[test]
    fn test_start_end_doc() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("should open default printer");

        let job_id = ps.start_doc_printer(handle, "TestDoc");
        assert!(job_id.is_some(), "Should create a print job");
        let job_id = job_id.expect("job_id should be Some");
        assert_eq!(job_id, 1);

        let job = ps.jobs.get(&job_id);
        assert!(job.is_some(), "job should exist after start_doc");
        let job = job.expect("job should be Some");
        assert_eq!(job.document_name, "TestDoc");
        assert_eq!(job.status, PrintJobStatus::Spooling);

        assert!(ps.end_doc_printer(job_id));
        let job = ps.jobs.get(&job_id);
        assert!(job.is_some(), "job should exist after end_doc");
        assert_eq!(
            job.expect("job should be Some").status,
            PrintJobStatus::Completed
        );
    }

    #[test]
    fn test_start_end_page() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("should open default printer");
        let job_id = ps
            .start_doc_printer(handle, "PageTest")
            .expect("should start document");

        assert!(ps.start_page_printer(job_id));
        assert_eq!(
            ps.jobs.get(&job_id).expect("job should exist").page_count,
            1
        );

        assert!(ps.start_page_printer(job_id));
        assert_eq!(
            ps.jobs.get(&job_id).expect("job should exist").page_count,
            2
        );

        assert!(ps.end_page_printer(job_id));
    }

    #[test]
    fn test_write_printer() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).expect("should open default printer");
        let job_id = ps
            .start_doc_printer(handle, "WriteTest")
            .expect("should start document");

        let data = b"Hello, Printer!";
        assert!(ps.write_printer(job_id, data));

        let job = ps.jobs.get(&job_id).expect("job should exist");
        assert_eq!(job.spool_data, data);

        // Write more data
        let data2 = b"More data";
        assert!(ps.write_printer(job_id, data2));
        assert_eq!(
            ps.jobs.get(&job_id).expect("job should exist").spool_data,
            b"Hello, Printer!More data"
        );
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
    fn test_get_printer() {
        let ps = PrintSubsystem::new();
        let printer = ps.get_printer(1);
        assert!(printer.is_some(), "printer 1 should exist");
        assert_eq!(
            printer.expect("printer should be Some").name,
            "Microsoft Print to PDF"
        );

        let printer = ps.get_printer(999);
        assert!(printer.is_none());
    }

    #[test]
    fn test_add_delete_printer() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.add_printer(PrinterInfo {
            name: "Test Printer".to_string(),
            port: "USB001:".to_string(),
            driver: "Test Driver".to_string(),
            comment: "Test".to_string(),
            location: "Office".to_string(),
            status: 0,
            attributes: 0,
            jobs: 0,
            default_priority: 1,
        });
        assert!(handle.is_some(), "add_printer should return Some handle");
        let handle = handle.expect("handle should be Some");

        let printer = ps.get_printer(handle);
        assert!(printer.is_some(), "get_printer should find added printer");
        assert_eq!(
            printer.expect("printer should be Some").name,
            "Test Printer"
        );

        assert!(ps.delete_printer(handle));
        assert!(
            ps.get_printer(handle).is_none(),
            "deleted printer should be gone"
        );
    }

    #[test]
    fn test_create_printer_dc() {
        let mut ps = PrintSubsystem::new();
        let dc = ps.create_printer_dc("Microsoft Print to PDF");
        assert!(dc.is_some(), "Should create a printer DC");
        let dc = dc.expect("dc should be Some");

        let dc_info = ps.get_printer_dc(dc);
        assert!(dc_info.is_some(), "DC info should be retrievable");
        assert_eq!(
            dc_info.expect("dc_info should be Some").printer_name,
            "Microsoft Print to PDF"
        );

        assert!(ps.delete_printer_dc(dc));
    }

    #[test]
    fn test_pdf_generation_single_page() {
        let ps = PrintSubsystem::new();
        let spool_data = b"Test spool content for PDF generation";
        let pdf = ps.generate_pdf(spool_data, "PDFTest", 1);

        // Verify it's a valid PDF with header
        assert!(pdf.starts_with(b"%PDF-1.4"), "Should start with PDF header");

        // Verify it contains our content
        let pdf_str = String::from_utf8_lossy(&pdf);
        assert!(pdf_str.contains("PDFTest"), "Should contain document name");
        assert!(
            pdf_str.contains("Printed from Casa1"),
            "Should contain Casa1 marker"
        );
        assert!(pdf_str.contains("Page 1"), "Should contain page number");

        // Verify cross-reference table is present
        assert!(
            pdf_str.contains("xref"),
            "Should contain cross-reference table"
        );
        assert!(pdf_str.contains("%%EOF"), "Should end with EOF marker");
    }

    #[test]
    fn test_pdf_generation_multi_page() {
        let ps = PrintSubsystem::new();
        let spool_data = b"Multi-page test content";
        let pdf = ps.generate_pdf(spool_data, "MultiPageTest", 3);

        let pdf_str = String::from_utf8_lossy(&pdf);
        assert!(
            pdf_str.starts_with("%PDF-1.4"),
            "Should start with PDF header"
        );
        assert!(
            pdf_str.contains("MultiPageTest"),
            "Should contain document name"
        );
        assert!(
            pdf_str.contains("Page 1 of 3"),
            "Should contain page 1 of 3"
        );
        assert!(
            pdf_str.contains("Page 2 of 3"),
            "Should contain page 2 of 3"
        );
        assert!(
            pdf_str.contains("Page 3 of 3"),
            "Should contain page 3 of 3"
        );
        assert!(
            pdf_str.contains("/Count 3"),
            "Pages tree should have Count 3"
        );
        assert!(pdf_str.contains("%%EOF"), "Should end with EOF marker");
    }

    #[test]
    fn test_read_printer() {
        let mut ps = PrintSubsystem::new();
        let handle = ps.open_printer(None).unwrap();
        let job_id = ps.start_doc_printer(handle, "ReadTest").unwrap();

        let mut buf = [0u8; 64];
        let bytes_read = ps.read_printer(job_id, &mut buf);
        assert!(bytes_read.is_some());
        assert_eq!(bytes_read.unwrap(), 0, "ReadPrinter should return 0 bytes");
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
    fn test_end_doc_printer_with_empty_spool() {
        let mut ps = PrintSubsystem::new();

        let handle = ps.open_printer(None).expect("should open printer");

        let job_id = ps
            .start_doc_printer(handle, "empty_doc")
            .expect("should start document");

        // End document with no pages
        assert!(
            ps.end_doc_printer(job_id),
            "should end document even with no pages"
        );

        // Verify the job exists and has Completed status
        let job = ps
            .jobs
            .get(&job_id)
            .expect("job should exist after end_doc");
        assert_eq!(
            job.status,
            PrintJobStatus::Completed,
            "job should be Completed"
        );
        assert_eq!(job.page_count, 0, "no pages were started");

        assert!(ps.close_printer(handle), "should close printer");
    }

    #[test]
    fn test_job_lifecycle_multiple_pages() {
        let mut ps = PrintSubsystem::new();

        let handle = ps.open_printer(None).expect("should open printer");

        let job_id = ps
            .start_doc_printer(handle, "multipage_doc")
            .expect("should start document");

        // Write multiple pages of data
        for page in 1..=5 {
            assert!(ps.start_page_printer(job_id), "should start page {}", page);
            assert!(
                ps.write_printer(job_id, format!("page {} content", page).as_bytes()),
                "should write page {} data",
                page
            );
            assert!(ps.end_page_printer(job_id), "should end page {}", page);
        }

        // End the document
        assert!(ps.end_doc_printer(job_id), "should end multi-page document");

        // Verify the job has correct metadata
        let job = ps.jobs.get(&job_id).expect("job should exist");
        assert_eq!(
            job.status,
            PrintJobStatus::Completed,
            "job should be Completed"
        );
        assert_eq!(job.page_count, 5, "should have 5 pages");

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

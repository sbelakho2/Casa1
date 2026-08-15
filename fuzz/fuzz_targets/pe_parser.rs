#![no_main]

use casa1::pe;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Determinism check via parse_summary
    let first = parse_summary(data);
    let second = parse_summary(data);
    assert_eq!(
        first, second,
        "pe::parse produced nondeterministic summaries for identical input"
    );

    // Test 2: If parsing succeeds, exercise higher-level PE APIs
    if let Ok(image) = pe::parse(data) {
        // Test resource blob lookup
        let _ = pe::find_resource_blob(
            data,
            &image.sections,
            &image.data_directories,
            0, // RT_CURSOR — any type ID exercises the code
        );

        // Test CLR header parsing (safe even when absent)
        let _ = pe::parse_clr_header(data, &image.sections, &image.data_directories);

        // Test resource icon extraction
        let _ = pe::find_resource_group_icons(data);

        // Test image mapping (requires a valid PE with sections)
        if !image.sections.is_empty() {
            let _ = pe::map_image(data, &image, "fuzz", false);
        }

        // Test activation context and manifest accessors
        if let Some(ref manifest) = image.embedded_manifest {
            let _plan = pe::build_activation_context(manifest);
        }
        if let Some(ref manifest) = image.external_manifest {
            let _plan = pe::build_activation_context(manifest);
        }
    }
});

fn parse_summary(data: &[u8]) -> String {
    match pe::parse(data) {
        Ok(image) => {
            // Summarise all major PE structures for determinism checking
            let mut parts = vec![format!(
                "ok:{}:{}:{}:{}:{}:{}:{}",
                image.machine,
                image.sections.len(),
                image.imports.len(),
                image.delay_imports.len(),
                image.exports.len(),
                image.relocations.len(),
                image.tls_directory.as_ref().map(|tls| tls.callbacks.len()).unwrap_or(0)
            )];

            // Add resource/manifest info
            let has_resources = image
                .data_directories
                .get(pe::IMAGE_DIRECTORY_ENTRY_RESOURCE)
                .map(|dd| dd.virtual_address != 0)
                .unwrap_or(false);
            parts.push(format!("resources:{}", has_resources));
            parts.push(format!("manifest:{}", image.embedded_manifest.is_some()));
            parts.push(format!("dotnet:{}", image.is_dotnet));
            parts.push(format!("bound_imports:{}", image.bound_imports.len()));
            parts.push(format!("debug:{}", image.debug_entries.len()));

            parts.join("|")
        }
        Err(error) => format!(
            "err:{}:{}:{}",
            error.code.as_u32(),
            error.message,
            error.reproduction_hints.join("|")
        ),
    }
}

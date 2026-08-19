//! API coverage evidence registry (oracle-backed).
//!
//! The registry maps (DLL, export) pairs to the ORACLE CONTRACT that proves
//! their semantic coverage.  Evidence is NEVER inferred from the existence of
//! a Rust test — each [`ApiCoverageEvidence`] row names the actual
//! differential-oracle contract (`windows-oracle:<category>`) that exercises
//! the API against the real Windows reference executable.
//!
//! [`ApiDatabase::from_thunk_metadata`] merges this registry after seeding
//! the implementation entries: when the (DLL, export, arch, Windows version)
//! key matches, the entry's [`CoverageLevel`] takes the registry's level.

use crate::api_database::{ArchSet, CoverageLevel, WindowsVersion};

/// One piece of oracle-backed coverage evidence for an API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiCoverageEvidence {
    /// Exporting DLL (lowercase, with extension).
    pub dll: &'static str,
    /// Export name.
    pub export: &'static str,
    /// Guest architectures the evidence applies to.
    pub arch: ArchSet,
    /// Windows versions the evidence applies to.
    pub windows_version: WindowsVersion,
    /// Proven semantic coverage level.
    pub level: CoverageLevel,
    /// The oracle contract that produces the evidence — the actual
    /// differential vector category the Windows reference executable runs.
    pub evidence_id: &'static str,
}

/// Convenience constructor for registry rows (any arch, any Windows version).
const fn evidence(
    dll: &'static str,
    export: &'static str,
    evidence_id: &'static str,
) -> ApiCoverageEvidence {
    ApiCoverageEvidence {
        dll,
        export,
        arch: ArchSet::Any,
        windows_version: WindowsVersion::Any,
        level: CoverageLevel::Differential,
        evidence_id,
    }
}

/// The static coverage-evidence registry.
///
/// Every row's `evidence_id` is a REAL oracle contract: the
/// `windows-oracle:<category>` differential vectors that the standalone
/// Windows reference executable (windows_reference/) runs.  An API may only
/// be promoted to `Differential` with one of these contracts behind it.
pub static COVERAGE_EVIDENCE: &[ApiCoverageEvidence] = &[
    evidence("kernel32.dll", "CreateFileW", "windows-oracle:file_sharing"),
    evidence(
        "kernel32.dll",
        "VirtualAlloc",
        "windows-oracle:virtual_memory",
    ),
    evidence("kernel32.dll", "TlsAlloc", "windows-oracle:thread_tls"),
    evidence("kernel32.dll", "lstrcmpiW", "windows-oracle:case_fold"),
    evidence("kernel32.dll", "CompareStringW", "windows-oracle:case_fold"),
    evidence(
        "kernel32.dll",
        "GetFullPathNameW",
        "windows-oracle:path_normalize",
    ),
    evidence("kernel32.dll", "LockFileEx", "windows-oracle:file_lock"),
    evidence("kernel32.dll", "UnlockFileEx", "windows-oracle:file_lock"),
    evidence(
        "kernel32.dll",
        "DeleteFileW",
        "windows-oracle:delete_semantics",
    ),
    evidence(
        "kernel32.dll",
        "CreateEventW",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "CreateMutexW",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "CreateSemaphoreW",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "WaitForSingleObject",
        "windows-oracle:synchronization",
    ),
    evidence(
        "kernel32.dll",
        "ReleaseMutex",
        "windows-oracle:synchronization",
    ),
    evidence("kernel32.dll", "RegOpenKeyExW", "windows-oracle:registry"),
    evidence(
        "kernel32.dll",
        "RegQueryValueExW",
        "windows-oracle:registry",
    ),
    evidence("kernel32.dll", "GetModuleHandleW", "windows-oracle:api_set"),
    evidence("kernel32.dll", "GetProcAddress", "windows-oracle:api_set"),
    // The d3d12 enum categories are covered by the Windows reference's
    // d3d12_* differential vectors.
    evidence(
        "d3d12.dll",
        "D3D12CreateDevice",
        "windows-oracle:d3d12_device",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateCommandQueue",
        "windows-oracle:d3d12_command_queue",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateCommandAllocator",
        "windows-oracle:d3d12_command_allocator",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateCommandList",
        "windows-oracle:d3d12_command_list",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCheckFeatureSupport",
        "windows-oracle:d3d12_feature_support",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateDescriptorHeap",
        "windows-oracle:d3d12_descriptor_heap",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateRenderTargetView",
        "windows-oracle:d3d12_render_target_view",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DeviceCreateFence",
        "windows-oracle:d3d12_fence",
    ),
    evidence(
        "d3d12.dll",
        "D3D12CommandQueueExecuteCommandLists",
        "windows-oracle:d3d12_command_queue",
    ),
    evidence(
        "d3d12.dll",
        "D3D12CommandQueueSignal",
        "windows-oracle:d3d12_fence",
    ),
    evidence(
        "d3d12.dll",
        "D3D12DescriptorHeapGetCpuHandleForHeapStart",
        "windows-oracle:d3d12_descriptor_heap",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListResourceBarrier",
        "windows-oracle:d3d12_resource_barrier",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListClearRenderTargetView",
        "windows-oracle:d3d12_render_target_view",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListDrawInstanced",
        "windows-oracle:d3d12_draw",
    ),
    evidence(
        "d3d12.dll",
        "D3D12GraphicsCommandListClose",
        "windows-oracle:d3d12_command_list",
    ),
];

/// Look up oracle-backed coverage evidence for a (DLL, export, arch, winver)
/// key, returning the strongest applicable evidence row.
pub fn coverage_evidence_for(
    dll: &str,
    export: &str,
    arch: ArchSet,
    windows_version: WindowsVersion,
) -> Option<&'static ApiCoverageEvidence> {
    let dll_key = dll.to_ascii_lowercase();
    COVERAGE_EVIDENCE.iter().find(|row| {
        row.dll.eq_ignore_ascii_case(&dll_key)
            && row.export.eq_ignore_ascii_case(export)
            && (row.arch == ArchSet::Any || row.arch == arch)
            && (row.windows_version == WindowsVersion::Any
                || row.windows_version == windows_version)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_never_inferred_from_rust_tests() {
        // Every row names a real oracle contract.
        for row in COVERAGE_EVIDENCE {
            assert!(
                row.evidence_id.starts_with("windows-oracle:"),
                "evidence must name the oracle contract, got {}",
                row.evidence_id
            );
            assert_eq!(row.level, CoverageLevel::Differential);
        }
    }

    #[test]
    fn registry_keys_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for row in COVERAGE_EVIDENCE {
            assert!(
                seen.insert((row.dll, row.export)),
                "duplicate evidence key {}!{}",
                row.dll,
                row.export
            );
        }
    }

    #[test]
    fn create_file_w_evidence_resolves() {
        let evidence = coverage_evidence_for(
            "KERNEL32.DLL",
            "createfilew",
            ArchSet::Any,
            WindowsVersion::Any,
        )
        .expect("CreateFileW evidence");
        assert_eq!(evidence.evidence_id, "windows-oracle:file_sharing");
        assert_eq!(evidence.level, CoverageLevel::Differential);
    }

    #[test]
    fn unknown_apis_have_no_evidence() {
        assert!(
            coverage_evidence_for(
                "kernel32.dll",
                "NoSuchExport",
                ArchSet::Any,
                WindowsVersion::Any
            )
            .is_none()
        );
    }
}

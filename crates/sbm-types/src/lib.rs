#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

/// Current canonical schema version string for v1 documents.
pub const SCHEMA_VERSION_V1: &str = "1.0";

/// Release manifest version that introduces combined boot media.
pub const RELEASE_MANIFEST_SCHEMA_VERSION_V1_1: &str = "1.1";

// ============================================================================
// 1. CPU Architecture, Firmware Platform & Capabilities (Spec 01)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum CpuArch {
    X86_64,
    Aarch64,
    Ia32,
    Riscv64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum FirmwarePlatform {
    UefiNative,
    UefiUboot,
    AppleSiliconM1n1Uboot,
    LegacyBios,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecureBootState {
    Disabled,
    Enabled,
    SetupMode,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct PlatformCapabilities {
    pub arch: CpuArch,
    pub firmware: FirmwarePlatform,
    pub page_size_bytes: u32,
    pub secure_boot_state: SecureBootState,
    pub tpm_present: bool,
    pub nvram_writable: bool,
    pub gop_framebuffer: bool,
    pub uefi_networking: bool,
    pub can_chainload_efi: bool,
    pub can_direct_chainload_macos: bool,
    pub external_usb_boot_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ram_total_mib: Option<u64>,
}

// ============================================================================
// 2. Boot Targets & Persistent Identifiers (Spec 01)
// ============================================================================

/// Stable, persistent identifier for a boot target (never derived from `/dev/sdX`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(transparent)]
pub struct BootTargetId(pub String);

impl BootTargetId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_valid(&self) -> bool {
        let s = self.0.as_str();
        !s.is_empty()
            && s.len() <= 160
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'-' | b'_' | b'.'))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Linux,
    Windows,
    MacOs,
    Bsd,
    Recovery,
    FirmwareUtility,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BootTargetKind {
    EfiBinary,
    BlsType1,
    BlsUki,
    SbmCore,
    AppleMacOsReboot,
    FirmwareSetup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootTarget {
    pub id: BootTargetId,
    pub display_name: String,
    pub os_family: OsFamily,
    pub kind: BootTargetKind,
    pub arch: CpuArch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub efi_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_cmdline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_hint: Option<String>,
    #[serde(default)]
    pub removable_media: bool,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_signature: Option<bool>,
}

// ============================================================================
// 3. Disk Identification, Storage Plans & Installation Plans (Spec 04)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum DiskBus {
    Nvme,
    Sata,
    Usb,
    Virtio,
    Scsi,
    Mmc,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct DiskIdentity {
    pub stable_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpt_disk_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wwn_or_eui64: Option<String>,
    pub model: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_hash: Option<String>,
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub bus: DiskBus,
    #[serde(default)]
    pub removable: bool,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum PartitionProtectionClass {
    Normal,
    ProtectedEsp,
    ProtectedAppleSystem,
    ProtectedEncrypted,
    ProtectedSbmRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum StorageOp {
    CreatePartition {
        start_lba: u64,
        end_lba: u64,
        type_guid: String,
        label: Option<String>,
    },
    ResizePartition {
        partition_guid: String,
        new_end_lba: u64,
    },
    FormatFilesystem {
        partition_guid: String,
        filesystem: String,
        label: Option<String>,
    },
    DeletePartition {
        partition_guid: String,
    },
    WriteImage {
        partition_guid: String,
        artifact_sha256: String,
    },
    ClonePartition {
        source_partition_guid: String,
        destination_partition_guid: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct StorageOperationPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub target_disk: DiskIdentity,
    pub expected_partition_table_sha256: String,
    pub operations: Vec<StorageOp>,
    pub destructive: bool,
    pub reversible: bool,
    #[serde(default)]
    pub touched_protected_classes: Vec<PartitionProtectionClass>,
    pub dry_run_summary: Vec<String>,
}

impl StorageOperationPlan {
    /// Returns true if any operation touches an Apple system partition or active recovery slot.
    pub fn blocks_by_default_safety(&self) -> bool {
        self.touched_protected_classes.iter().any(|c| {
            matches!(
                c,
                PartitionProtectionClass::ProtectedAppleSystem
                    | PartitionProtectionClass::ProtectedSbmRecovery
                    | PartitionProtectionClass::ProtectedEncrypted
            )
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum InstallStrategy {
    DirectInstallerBoot,
    RootfsImageExtract,
    BootcOci,
    WindowsWimApply,
    BsdImage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct VerifiedArtifactRef {
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub source_url_or_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootRegistrationPlan {
    pub register_bls_or_efi: bool,
    pub set_as_default: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct OsInstallPlan {
    pub schema_version: String,
    pub plan_id: String,
    pub catalog_entry_id: String,
    pub catalog_release_version: String,
    pub target_arch: CpuArch,
    pub strategy: InstallStrategy,
    pub artifact_verification: Vec<VerifiedArtifactRef>,
    pub storage_plan: StorageOperationPlan,
    pub boot_registration: BootRegistrationPlan,
    #[serde(default)]
    pub offline_media_only: bool,
}

// ============================================================================
// 4. OS Catalog Definitions (Spec 05)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Stable,
    Lts,
    Rolling,
    Beta,
    Nightly,
    Testing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct CatalogArtifact {
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha512: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_signature_url: Option<String>,
    pub mirrors: Vec<String>,
    #[serde(default)]
    pub user_supplied_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct OsReleaseEntry {
    pub version: String,
    pub channel: ReleaseChannel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eol_date: Option<String>,
    pub architectures: Vec<CpuArch>,
    pub supported_platforms: Vec<FirmwarePlatform>,
    pub min_ram_mib: u32,
    pub min_disk_gib: u32,
    pub install_strategy: InstallStrategy,
    pub artifacts: Vec<CatalogArtifact>,
    pub recipe_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct OsCatalogEntry {
    pub schema_version: String,
    pub id: String,
    pub name: String,
    pub os_family: OsFamily,
    pub vendor: String,
    pub homepage_url: String,
    pub releases: Vec<OsReleaseEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct CatalogIndex {
    pub schema_version: String,
    pub catalog_revision: u64,
    pub published_at_unix: i64,
    pub entries: Vec<OsCatalogEntry>,
}

// ============================================================================
// 5. Releases & Diagnostics (Spec 07)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ComponentKind {
    SbmUefi,
    SbmCoreUki,
    SbmCoreSysext,
    SbmAsBootstrap,
    SbmInstaller,
    SbmServer,
    SbmAgent,
    SbmCatalog,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ReleaseArtifact {
    pub component: ComponentKind,
    pub arch: CpuArch,
    pub platform: FirmwarePlatform,
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sbat_generation: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_bundle_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ReleaseMedia {
    pub filename: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub architectures: Vec<CpuArch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ReleaseManifest {
    pub schema_version: String,
    pub release_version: String,
    pub channel: ReleaseChannel,
    pub published_at_unix: i64,
    pub git_commit: String,
    pub minimum_protocol_major: u16,
    pub minimum_protocol_minor: u16,
    pub artifacts: Vec<ReleaseArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub media: Vec<ReleaseMedia>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum SbmErrorCode {
    InvalidSchema,
    SignatureInvalid,
    ReplayDetected,
    CommandExpired,
    UnauthorizedScope,
    ProtectedPartitionBlocked,
    DiskIdentityMismatch,
    NetworkTimeout,
    TargetNotFound,
    ChainloadFailed,
    IncompatibleProtocolVersion,
    StorageIoError,
    UnsupportedPlatform,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct SbmError {
    pub code: SbmErrorCode,
    pub component: ComponentKind,
    pub recoverable: bool,
    pub message: String,
    #[serde(default)]
    pub context: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct DiagnosticBundle {
    pub schema_version: String,
    pub generated_at_unix: Option<i64>,
    pub platform: PlatformCapabilities,
    pub errors: Vec<SbmError>,
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn boot_target_id_validation() {
        assert!(BootTargetId("efi:1234-5678:abcdef012345".to_string()).is_valid());
        assert!(BootTargetId("sbm-core:slot-a".to_string()).is_valid());
        assert!(!BootTargetId(String::new()).is_valid());
        assert!(!BootTargetId("bad target/with spaces".to_string()).is_valid());
    }

    #[test]
    fn protected_apple_partition_blocks_by_default() {
        let plan = StorageOperationPlan {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            plan_id: "019a0000-0000-7000-8000-000000000001".to_string(),
            target_disk: DiskIdentity {
                stable_id: "gpt:11111111-2222-3333-4444-555555555555".to_string(),
                gpt_disk_guid: Some("11111111-2222-3333-4444-555555555555".to_string()),
                wwn_or_eui64: None,
                model: "Virtual NVMe".to_string(),
                serial_hash: None,
                size_bytes: 64 * 1024 * 1024 * 1024,
                logical_sector_size: 4096,
                bus: DiskBus::Nvme,
                removable: false,
                read_only: false,
            },
            expected_partition_table_sha256: "0".repeat(64),
            operations: vec![],
            destructive: true,
            reversible: false,
            touched_protected_classes: vec![PartitionProtectionClass::ProtectedAppleSystem],
            dry_run_summary: vec!["Blocked test".to_string()],
        };
        assert!(plan.blocks_by_default_safety());
    }
}

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use sbm_types::{
    BootTarget, BootTargetId, ComponentKind, OsInstallPlan, PlatformCapabilities, SbmErrorCode,
    StorageOperationPlan,
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "schema")]
use schemars::JsonSchema;

pub const PROTOCOL_V1: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };
pub const COMMAND_SIGNING_DOMAIN_V1: &[u8] = b"sbm-cmd-v1\0";

mod canonical;
pub use canonical::{command_canonical_json, command_signing_preimage};

// ============================================================================
// 1. Compatibility Negotiation (Spec 07)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct CapabilityHello {
    pub component: ComponentKind,
    pub software_version: String,
    pub supported_protocol_min: ProtocolVersion,
    pub supported_protocol_max: ProtocolVersion,
    #[serde(default)]
    pub features: Vec<String>,
}

/// Negotiate the highest compatible protocol version sharing a major version.
pub fn negotiate_protocol(
    a_min: ProtocolVersion,
    a_max: ProtocolVersion,
    b_min: ProtocolVersion,
    b_max: ProtocolVersion,
) -> Result<ProtocolVersion, SbmErrorCode> {
    if a_min > a_max || b_min > b_max {
        return Err(SbmErrorCode::InvalidSchema);
    }
    let low = if a_min > b_min { a_min } else { b_min };
    let high = if a_max < b_max { a_max } else { b_max };
    if low <= high && low.major == high.major {
        Ok(high)
    } else if low <= high {
        // Pick the highest shared major version within overlap
        Ok(ProtocolVersion {
            major: high.major,
            minor: high.minor,
        })
    } else {
        Err(SbmErrorCode::IncompatibleProtocolVersion)
    }
}

// ============================================================================
// 2. Boot Commands, Policies & Attempt Reporting (Spec 02)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecoverySlotPreference {
    Auto,
    SlotA,
    SlotB,
    Removable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum RecoveryLaunchMode {
    Interactive,
    RemoteAssist,
    DiagnosticOnly,
    PlannedOperation { plan_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum BootCommand {
    BootTarget {
        target_id: BootTargetId,
        one_shot: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        extra_cmdline_preset: Option<String>,
    },
    BootRecovery {
        slot: RecoverySlotPreference,
        launch_mode: RecoveryLaunchMode,
    },
    RebootToFirmwareSetup,
    Reboot,
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct OneShotBoot {
    pub target_id: BootTargetId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<i64>,
    #[serde(default)]
    pub consumed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum OfflineBehavior {
    UseLocalPolicy,
    WaitForUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootPolicy {
    pub schema_version: String,
    pub policy_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_target: Option<BootTargetId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_target: Option<BootTargetId>,
    pub timeout_seconds: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub one_shot: Option<OneShotBoot>,
    pub max_failed_attempts: u8,
    pub network_policy_timeout_ms: u32,
    #[serde(default)]
    pub allow_remote_boot_select: bool,
    pub offline_behavior: OfflineBehavior,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BootAttemptStatus {
    Started,
    Confirmed,
    Failed,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootAttemptRecord {
    pub schema_version: String,
    pub attempt_id: String,
    pub target_id: BootTargetId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_unix: Option<i64>,
    pub consecutive_failures: u8,
    pub status: BootAttemptStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootSuccessReport {
    pub schema_version: String,
    pub attempt_id: String,
    pub target_id: BootTargetId,
    pub confirmed_by: ComponentKind,
    pub confirmed_at_unix: i64,
}

/// A one-shot boot request that SBM Core writes to
/// `\EFI\sbm\handoff\requested-command.json` on the boot ESP for the next
/// picker start (Spec 02 §5a).
///
/// The request is bound to the recovery attempt Core ran under. The picker
/// honours it only when `attempt_id` names its current confirmed
/// `sbm-core:slot-a` attempt and the target is one it can launch now. It
/// deletes the file before acting, so a request is never replayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct LocalBootRequest {
    pub schema_version: String,
    /// Fresh UUIDv4 for this request.
    pub request_id: String,
    /// `attempt_id` of the verified handoff of the Core session that wrote it.
    pub attempt_id: String,
    pub requested_by: ComponentKind,
    pub requested_at_unix: i64,
    /// 0.0.1 accepts only `BootTarget` with `one_shot = true`.
    pub command: BootCommand,
}

/// Format 16 random bytes as an RFC 9562 version 4 UUID (lowercase).
pub fn format_uuid_v4(mut bytes: [u8; 16]) -> String {
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(36);
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

/// True for a lowercase or uppercase RFC 9562 version 4 UUID string.
pub fn is_uuid_v4(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let dash = matches!(index, 8 | 13 | 18 | 23);
        if dash != (*byte == b'-') || (!dash && !byte.is_ascii_hexdigit()) {
            return false;
        }
    }
    bytes[14] == b'4' && matches!(bytes[19], b'8' | b'9' | b'a' | b'b' | b'A' | b'B')
}

// ============================================================================
// 3. EFI-to-Linux Handoff & Recovery Discovery (Spec 03)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct BootTimingMetrics {
    pub firmware_init_us: Option<u64>,
    pub uefi_entry_us: u64,
    pub first_frame_us: Option<u64>,
    pub network_us: Option<u64>,
    pub handoff_us: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct NetworkHandoffHint {
    pub link_up: bool,
    pub dhcp_acquired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_reachable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct EfiHandoffPayload {
    pub schema_version: String,
    pub attempt_id: String,
    pub sbm_uefi_version: String,
    pub platform: PlatformCapabilities,
    pub launch_mode: RecoveryLaunchMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_command_id: Option<String>,
    pub discovered_targets: Vec<BootTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_timing_us: Option<BootTimingMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_hint: Option<NetworkHandoffHint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RecoverySlotDescriptor {
    pub slot_name: String,
    pub uki_efi_path: String,
    pub sha256: String,
    pub version: String,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct RecoveryManifest {
    pub schema_version: String,
    pub active_slot: String,
    pub slots: Vec<RecoverySlotDescriptor>,
}

// ============================================================================
// 4. Remote Enrollment, AuthZ & Signed Command Envelopes (Spec 06)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum AuthScope {
    ReadOnly,
    BootSelect,
    RecoveryAccess,
    OsInstall,
    StorageDestructive,
    Admin,
}

impl AuthScope {
    /// Strict security invariant: `sbm-uefi` may ONLY accept `ReadOnly` or `BootSelect`.
    pub fn is_allowed_in_uefi(self) -> bool {
        matches!(self, AuthScope::ReadOnly | AuthScope::BootSelect)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct EnrollmentRequest {
    pub schema_version: String,
    pub enrollment_token: String,
    pub device_public_key_ed25519_hex: String,
    pub hostname: String,
    pub platform: PlatformCapabilities,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tpm_attestation_b64: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct EnrollmentResponse {
    pub schema_version: String,
    pub device_id: String,
    pub client_cert_pem: String,
    pub server_command_verify_key_ed25519_hex: String,
    pub granted_scopes: Vec<AuthScope>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CommandPayload {
    Boot(BootCommand),
    RunStoragePlan(StorageOperationPlan),
    RunOsInstall(OsInstallPlan),
    RevokeEnrollment { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct CommandEnvelope {
    pub schema_version: String,
    pub command_id: String,
    pub device_id: String,
    pub sequence: u64,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub required_scope: AuthScope,
    pub issuer_key_id: String,
    pub payload: CommandPayload,
    pub signature_ed25519_hex: String,
}

impl CommandEnvelope {
    /// Validate binding, anti-replay sequence, TTL (if clock provided), and environment scope.
    /// Cryptographic Ed25519 signature verification MUST be called in addition to this check.
    pub fn validate_metadata(
        &self,
        expected_device_id: &str,
        last_seen_sequence: u64,
        now_unix: Option<i64>,
        executing_in_uefi: bool,
    ) -> Result<(), SbmErrorCode> {
        if self.device_id != expected_device_id {
            return Err(SbmErrorCode::UnauthorizedScope);
        }
        if self.sequence <= last_seen_sequence {
            return Err(SbmErrorCode::ReplayDetected);
        }
        if self.expires_at_unix <= self.issued_at_unix {
            return Err(SbmErrorCode::InvalidSchema);
        }
        if let Some(now) = now_unix
            && now > self.expires_at_unix
        {
            return Err(SbmErrorCode::CommandExpired);
        }
        if executing_in_uefi {
            if !self.required_scope.is_allowed_in_uefi() {
                return Err(SbmErrorCode::UnauthorizedScope);
            }
            if !matches!(self.payload, CommandPayload::Boot(_)) {
                return Err(SbmErrorCode::UnauthorizedScope);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use sbm_types::SCHEMA_VERSION_V1;

    #[test]
    fn uuid_v4_formatting_sets_version_and_variant() {
        let id = format_uuid_v4([0xff; 16]);
        assert_eq!(id, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert!(is_uuid_v4(&id));
        let id = format_uuid_v4([0; 16]);
        assert_eq!(id, "00000000-0000-4000-8000-000000000000");
        assert!(is_uuid_v4(&id));
        assert!(!is_uuid_v4("uefi-1727508"));
        assert!(!is_uuid_v4("local"));
        assert!(!is_uuid_v4("019a0000-0000-7000-8000-000000000202"));
        assert!(!is_uuid_v4("00000000-0000-4000-c000-000000000000"));
        assert!(!is_uuid_v4("00000000x0000-4000-8000-000000000000"));
    }

    #[test]
    fn protocol_negotiation_works() {
        let v1_0 = ProtocolVersion { major: 1, minor: 0 };
        let v1_2 = ProtocolVersion { major: 1, minor: 2 };
        let v2_0 = ProtocolVersion { major: 2, minor: 0 };

        assert_eq!(negotiate_protocol(v1_0, v1_2, v1_0, v1_0), Ok(v1_0));
        assert_eq!(
            negotiate_protocol(v1_0, v1_2, v2_0, v2_0),
            Err(SbmErrorCode::IncompatibleProtocolVersion)
        );
    }

    #[test]
    fn uefi_rejects_destructive_and_replayed_commands() {
        let env = CommandEnvelope {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            command_id: "019a0000-0000-7000-8000-000000000009".to_string(),
            device_id: "dev-01".to_string(),
            sequence: 5,
            issued_at_unix: 1_795_000_000,
            expires_at_unix: 1_795_003_600,
            required_scope: AuthScope::BootSelect,
            issuer_key_id: "key-1".to_string(),
            payload: CommandPayload::Boot(BootCommand::BootTarget {
                target_id: BootTargetId("sbm-core:slot-a".to_string()),
                one_shot: true,
                extra_cmdline_preset: None,
            }),
            signature_ed25519_hex: "00".repeat(64),
        };

        assert_eq!(
            env.validate_metadata("dev-01", 4, Some(1_795_000_100), true),
            Ok(())
        );
        assert_eq!(
            env.validate_metadata("dev-01", 5, Some(1_795_000_100), true),
            Err(SbmErrorCode::ReplayDetected)
        );
        assert_eq!(
            env.validate_metadata("dev-01", 4, Some(1_795_009_999), true),
            Err(SbmErrorCode::CommandExpired)
        );
        assert_eq!(
            env.validate_metadata("dev-other", 4, Some(1_795_000_100), true),
            Err(SbmErrorCode::UnauthorizedScope)
        );

        let mut bad_scope = env;
        bad_scope.required_scope = AuthScope::StorageDestructive;
        assert_eq!(
            bad_scope.validate_metadata("dev-01", 4, Some(1_795_000_100), true),
            Err(SbmErrorCode::UnauthorizedScope)
        );
    }

    #[test]
    fn signing_bytes_match_the_published_boot_vector() {
        let env = CommandEnvelope {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            command_id: "019a0000-0000-7000-8000-000000000101".to_string(),
            device_id: "dev-qemu-01".to_string(),
            sequence: 1,
            issued_at_unix: 1_795_000_000,
            expires_at_unix: 1_795_003_600,
            required_scope: AuthScope::BootSelect,
            issuer_key_id: "sbm-server-ed25519-01".to_string(),
            payload: CommandPayload::Boot(BootCommand::BootTarget {
                target_id: BootTargetId("sbm-core:slot-a".to_string()),
                one_shot: true,
                extra_cmdline_preset: None,
            }),
            signature_ed25519_hex: "00".repeat(64),
        };
        let json = command_canonical_json(&env).expect("json");
        assert_eq!(
            json,
            concat!(
                r#"{"schema_version":"1.0","command_id":"019a0000-0000-7000-8000-000000000101","#,
                r#""device_id":"dev-qemu-01","sequence":1,"issued_at_unix":1795000000,"#,
                r#""expires_at_unix":1795003600,"required_scope":"boot_select","#,
                r#""issuer_key_id":"sbm-server-ed25519-01","payload":{"kind":"boot","#,
                r#""action":"boot_target","target_id":"sbm-core:slot-a","one_shot":true}}"#,
            )
            .as_bytes()
        );
        let preimage = command_signing_preimage(&env).expect("preimage");
        assert!(preimage.starts_with(COMMAND_SIGNING_DOMAIN_V1));
        assert_eq!(
            &preimage[COMMAND_SIGNING_DOMAIN_V1.len()..],
            json.as_slice()
        );
    }
}

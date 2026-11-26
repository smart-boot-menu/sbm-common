#![forbid(unsafe_code)]

use sbm_protocol::{
    BootAttemptRecord, BootPolicy, BootSuccessReport, CapabilityHello, CommandEnvelope,
    EfiHandoffPayload, EnrollmentRequest, EnrollmentResponse, RecoveryManifest,
};
use sbm_types::{
    BootTarget, CatalogIndex, DiagnosticBundle, OsCatalogEntry, OsInstallPlan,
    PlatformCapabilities, ReleaseManifest, SbmError, StorageOperationPlan,
};
use schemars::schema_for;
use serde_json::Value;

pub struct NamedSchema {
    pub filename: &'static str,
    pub schema: Value,
}

/// Generate all canonical v1 JSON Schemas from the Rust types.
pub fn all_schemas() -> Vec<NamedSchema> {
    vec![
        NamedSchema {
            filename: "platform-capabilities.v1.schema.json",
            schema: serde_json::to_value(schema_for!(PlatformCapabilities)).unwrap(),
        },
        NamedSchema {
            filename: "boot-target.v1.schema.json",
            schema: serde_json::to_value(schema_for!(BootTarget)).unwrap(),
        },
        NamedSchema {
            filename: "boot-policy.v1.schema.json",
            schema: serde_json::to_value(schema_for!(BootPolicy)).unwrap(),
        },
        NamedSchema {
            filename: "boot-attempt-record.v1.schema.json",
            schema: serde_json::to_value(schema_for!(BootAttemptRecord)).unwrap(),
        },
        NamedSchema {
            filename: "boot-success-report.v1.schema.json",
            schema: serde_json::to_value(schema_for!(BootSuccessReport)).unwrap(),
        },
        NamedSchema {
            filename: "efi-handoff.v1.schema.json",
            schema: serde_json::to_value(schema_for!(EfiHandoffPayload)).unwrap(),
        },
        NamedSchema {
            filename: "recovery-manifest.v1.schema.json",
            schema: serde_json::to_value(schema_for!(RecoveryManifest)).unwrap(),
        },
        NamedSchema {
            filename: "storage-operation-plan.v1.schema.json",
            schema: serde_json::to_value(schema_for!(StorageOperationPlan)).unwrap(),
        },
        NamedSchema {
            filename: "os-install-plan.v1.schema.json",
            schema: serde_json::to_value(schema_for!(OsInstallPlan)).unwrap(),
        },
        NamedSchema {
            filename: "os-catalog-entry.v1.schema.json",
            schema: serde_json::to_value(schema_for!(OsCatalogEntry)).unwrap(),
        },
        NamedSchema {
            filename: "catalog-index.v1.schema.json",
            schema: serde_json::to_value(schema_for!(CatalogIndex)).unwrap(),
        },
        NamedSchema {
            filename: "enrollment-request.v1.schema.json",
            schema: serde_json::to_value(schema_for!(EnrollmentRequest)).unwrap(),
        },
        NamedSchema {
            filename: "enrollment-response.v1.schema.json",
            schema: serde_json::to_value(schema_for!(EnrollmentResponse)).unwrap(),
        },
        NamedSchema {
            filename: "command-envelope.v1.schema.json",
            schema: serde_json::to_value(schema_for!(CommandEnvelope)).unwrap(),
        },
        NamedSchema {
            filename: "release-manifest.v1.schema.json",
            schema: serde_json::to_value(schema_for!(ReleaseManifest)).unwrap(),
        },
        NamedSchema {
            filename: "capability-hello.v1.schema.json",
            schema: serde_json::to_value(schema_for!(CapabilityHello)).unwrap(),
        },
        NamedSchema {
            filename: "sbm-error.v1.schema.json",
            schema: serde_json::to_value(schema_for!(SbmError)).unwrap(),
        },
        NamedSchema {
            filename: "diagnostic-bundle.v1.schema.json",
            schema: serde_json::to_value(schema_for!(DiagnosticBundle)).unwrap(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn all_schemas_are_valid_json_objects() {
        let schemas = all_schemas();
        assert_eq!(schemas.len(), 18);
        for s in schemas {
            assert!(s.schema.is_object(), "{} must be a JSON object", s.filename);
            assert!(
                s.schema.get("title").is_some(),
                "{} must contain a title",
                s.filename
            );
        }
    }

    #[test]
    fn golden_test_vectors_roundtrip() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let vec_dir = root.join("test-vectors");
        if !vec_dir.exists() {
            return;
        }
        let policy_raw = fs::read_to_string(vec_dir.join("boot-policy.v1.json")).unwrap();
        let policy: BootPolicy = serde_json::from_str(&policy_raw).unwrap();
        assert_eq!(policy.schema_version, "1.0");

        let env_raw = fs::read_to_string(vec_dir.join("command-envelope.v1.json")).unwrap();
        let env: CommandEnvelope = serde_json::from_str(&env_raw).unwrap();
        assert!(
            env.validate_metadata("dev-qemu-01", 0, Some(1_795_000_500), true)
                .is_ok()
        );

        let handoff_raw = fs::read_to_string(vec_dir.join("efi-handoff.v1.json")).unwrap();
        let handoff: EfiHandoffPayload = serde_json::from_str(&handoff_raw).unwrap();
        assert_eq!(handoff.schema_version, "1.0");

        let recovery_raw = fs::read_to_string(vec_dir.join("recovery-manifest.v1.json")).unwrap();
        let recovery: RecoveryManifest = serde_json::from_str(&recovery_raw).unwrap();
        assert_eq!(recovery.schema_version, "1.0");
        assert_eq!(recovery.slots.len(), 2);
        assert!(
            recovery
                .slots
                .iter()
                .all(|slot| slot.slot_name == recovery.active_slot)
        );
        assert_eq!(
            serde_json::to_value(&recovery).unwrap(),
            serde_json::from_str::<serde_json::Value>(&recovery_raw).unwrap()
        );

        let cat_raw = fs::read_to_string(vec_dir.join("os-catalog-entry.v1.json")).unwrap();
        let cat: OsCatalogEntry = serde_json::from_str(&cat_raw).unwrap();
        assert_eq!(cat.id, "fedora-workstation");
    }

    #[test]
    fn release_manifest_media_preserves_v1_compatibility() {
        use sbm_types::{CpuArch, RELEASE_MANIFEST_SCHEMA_VERSION_V1_1, SCHEMA_VERSION_V1};

        let sample = include_str!("../../../test-vectors/release-manifest.v1.1.json");
        let manifest: ReleaseManifest = serde_json::from_str(sample).unwrap();
        assert_eq!(
            manifest.schema_version,
            RELEASE_MANIFEST_SCHEMA_VERSION_V1_1
        );
        assert_eq!(manifest.media.len(), 2);
        for media in &manifest.media {
            assert_eq!(media.architectures, [CpuArch::X86_64, CpuArch::Aarch64]);
        }
        assert_eq!(
            serde_json::to_value(&manifest).unwrap(),
            serde_json::from_str::<serde_json::Value>(sample).unwrap()
        );

        let mut legacy = serde_json::to_value(&manifest).unwrap();
        legacy["schema_version"] = SCHEMA_VERSION_V1.into();
        legacy.as_object_mut().unwrap().remove("media");
        let manifest: ReleaseManifest = serde_json::from_value(legacy.clone()).unwrap();
        assert!(manifest.media.is_empty());
        assert_eq!(serde_json::to_value(&manifest).unwrap(), legacy);
    }
}

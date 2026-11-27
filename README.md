# Smart Boot Menu — Shared Libraries & Schemas (`sbm-common`)

Canonical Rust crates, JSON Schemas, and golden protocol test vectors implementing the normative specifications in [`smart-boot-menu/docs/specifications/`](https://github.com/smart-boot-menu/docs/tree/main/specifications).

## Crates

| Crate | `no_std` + `alloc`? | Purpose |
|---|---|---|
| `sbm-types` | **Yes** (`--no-default-features`) | Identifiers, `PlatformCapabilities`, `BootTarget`, `DiskIdentity`, `StorageOperationPlan`, `OsInstallPlan`, `OsCatalogEntry`, `ReleaseManifest`, `SbmError` |
| `sbm-protocol` | **Yes** (`--no-default-features`) | `ProtocolVersion` negotiation, `BootPolicy`, `BootCommand`, `BootAttemptRecord`, `LocalBootRequest`, `EfiHandoffPayload`, `RecoveryManifest`, `EnrollmentRequest/Response`, `AuthScope`, `CommandEnvelope`, `command_signing_preimage` |
| `sbm-schema` | `std` only | Exports 19 canonical JSON Schemas to `schemas/` and validates golden `test-vectors/` |

`command_signing_preimage` is Command Signing Profile v1: `COMMAND_SIGNING_DOMAIN_V1` followed by the compact JSON of every envelope field except `signature_ed25519_hex`. A UEFI verifier and `sbm-server` both call it. `test-vectors/command-signing.v1.json` locks a published test seed (not a production key) and the signatures for boot, recovery, and revoke. `test-vectors/command-envelope.v1.json` is the envelope shape.

## Release manifest migration

`ReleaseManifest.media` defaults to an empty vector when reading existing 1.0 JSON. Follow Spec 07 and use `RELEASE_MANIFEST_SCHEMA_VERSION_V1_1` when producing media entries. Update Rust struct literals to include the new field. Consumers that distribute combined media must explicitly accept 1.1 and validate the media metadata. The schema file retains its v1 family name. Recovery, handoff, and command-envelope wire versions stay at 1.0.

## Verification Commands

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p sbm-types -p sbm-protocol --no-default-features --target x86_64-unknown-uefi
cargo check -p sbm-types -p sbm-protocol --no-default-features --target aarch64-unknown-uefi
cargo run -p sbm-schema -- schemas
```

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE).

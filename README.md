# Smart Boot Menu — Shared Libraries & Schemas (`sbm-common`)

Canonical Rust crates, JSON Schemas, and golden protocol test vectors implementing the normative specifications in [`smart-boot-menu/docs/specifications/`](https://github.com/smart-boot-menu/docs/tree/main/specifications).

## Crates

| Crate | `no_std` + `alloc`? | Purpose |
|---|---|---|
| `sbm-types` | **Yes** (`--no-default-features`) | Identifiers, `PlatformCapabilities`, `BootTarget`, `DiskIdentity`, `StorageOperationPlan`, `OsInstallPlan`, `OsCatalogEntry`, `ReleaseManifest`, `SbmError` |
| `sbm-protocol` | **Yes** (`--no-default-features`) | `ProtocolVersion` negotiation, `BootPolicy`, `BootCommand`, `BootAttemptRecord`, `EfiHandoffPayload`, `RecoveryManifest`, `EnrollmentRequest/Response`, `AuthScope`, `CommandEnvelope` |
| `sbm-schema` | `std` only | Exports 18 canonical JSON Schemas to `schemas/` and validates golden `test-vectors/` |

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

# AGENTS.md — `sbm-common`

Follow the universal Smart Boot Menu agent rules in [`smart-boot-menu/.github/AGENTS.md`](https://github.com/smart-boot-menu/.github/blob/main/AGENTS.md) (locally `../.github/AGENTS.md`).

## Repository Role

`smart-boot-menu/sbm-common` is the **single canonical Rust & JSON Schema implementation** of all Smart Boot Menu shared interfaces (`docs/specifications/01..07`).

## Strict Rules

1. **`no_std` + `alloc` Guarantee:** `sbm-types` and `sbm-protocol` MUST always compile with `--no-default-features` for BOTH `x86_64-unknown-uefi` and `aarch64-unknown-uefi`. Never add OS-dependent crates to their non-`std` dependency graph.
2. **`#![forbid(unsafe_code)]`:** Keep all crates in `sbm-common` 100% safe Rust.
3. **Spec Synchronization:** Every structural change MUST correspond to a specification PR in `smart-boot-menu/docs/specifications/`, regenerate `schemas/*.schema.json` via `cargo run -p sbm-schema -- schemas`, and update `test-vectors/*.json`.
4. **Keep It Lean:** Only define shared data types, serialization, protocol validation, and schemas — never pull in UEFI `uefi-rs`, `tokio`, `axum`, or Linux syscalls here.

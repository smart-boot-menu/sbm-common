# AGENTS.md — `sbm-common`

## Canonical Organization Policy (Read First)

Before designing or implementing changes, read the canonical organization-wide engineering rules in [`smart-boot-menu/.github/AGENTS.md`](https://github.com/smart-boot-menu/.github/blob/main/AGENTS.md) (local workspace: `../.github/AGENTS.md`), the operational checklists in [`.github/agent-reference.md`](https://github.com/smart-boot-menu/.github/blob/main/agent-reference.md) (`../.github/agent-reference.md`), and the **Open-Source Reuse & Engineering Principles** in [`ADR-010`](https://github.com/smart-boot-menu/docs/blob/main/architecture-decisions/ADR-010-open-source-reuse-and-engineering-principles.md) (`../docs/architecture-decisions/ADR-010-open-source-reuse-and-engineering-principles.md`).

> **Standalone / Single-Repo Agents:** If you were launched inside this repository alone and `../.github/AGENTS.md` is not present locally, fetch and follow the GitHub URLs above before proceeding. Do not recreate inferior versions of existing software; apply proportional build-versus-reuse evaluation for new components, major dependencies, architectural changes, or replacements.

## Repository Role

`smart-boot-menu/sbm-common` is the **single canonical Rust & JSON Schema implementation** of all Smart Boot Menu shared interfaces (`docs/specifications/01..07`).

## Strict Rules

1. **`no_std` + `alloc` Guarantee:** `sbm-types` and `sbm-protocol` MUST always compile with `--no-default-features` for BOTH `x86_64-unknown-uefi` and `aarch64-unknown-uefi`. Never add OS-dependent crates to their non-`std` dependency graph.
2. **`#![forbid(unsafe_code)]`:** Keep all crates in `sbm-common` 100% safe Rust.
3. **Spec Synchronization:** Every structural change MUST correspond to a specification PR in `smart-boot-menu/docs/specifications/`, regenerate `schemas/*.schema.json` via `cargo run -p sbm-schema -- schemas`, and update `test-vectors/*.json`.
4. **Keep It Lean:** Only define shared data types, serialization, protocol validation, and schemas — never pull in UEFI `uefi-rs`, `tokio`, `axum`, or Linux syscalls here.

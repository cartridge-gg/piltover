//! SPDX-License-Identifier: MIT
//!
//! Versioned report-data tags for Katana TEE attestations.
//!
//! These mirror the Rust constants in `katana_rpc_api::tee`
//! (`KATANA_TEE_REPORT_VERSION`, `KATANA_TEE_APPCHAIN_MODE`) so the on-chain v1
//! commitment matches the off-chain one byte-for-byte.
//!
//! The config hash itself (`KatanaTeeConfig1`-tagged Pedersen-array hash of
//! `[chain_id, fee_token_address]`) is computed off-chain by Katana RPC and
//! stored on-chain in `KatanaTeeProgramInfo.katana_tee_config_hash`. The
//! on-chain side stores and compares but does not recompute, so no `KatanaTeeConfig1`
//! tag is needed here.

/// Domain tag for the v1 Katana TEE report-data schema.
pub const KATANA_TEE_REPORT_VERSION: felt252 = 'KatanaTeeReport1';

/// Mode tag for appchain settlement attestations.
pub const KATANA_TEE_APPCHAIN_MODE: felt252 = 'KatanaTeeAppchain';

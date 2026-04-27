//! SPDX-License-Identifier: MIT
//!
//! Versioned config-hash and report-data tags for Katana TEE attestations.
//!
//! These mirror the Rust constants in
//! `katana_rpc_api::tee` (`KATANA_TEE_CONFIG_VERSION`, `KATANA_TEE_REPORT_VERSION`,
//! `KATANA_TEE_APPCHAIN_MODE`) so the on-chain v1 commitment matches the off-chain
//! one byte-for-byte.

use core::pedersen::pedersen;
use starknet::ContractAddress;

/// Domain tag for the Katana TEE environment config hash.
pub const KATANA_TEE_CONFIG_VERSION: felt252 = 'KatanaTeeConfig1';

/// Domain tag for the v1 Katana TEE report-data schema.
pub const KATANA_TEE_REPORT_VERSION: felt252 = 'KatanaTeeReport1';

/// Mode tag for appchain settlement attestations.
pub const KATANA_TEE_APPCHAIN_MODE: felt252 = 'KatanaTeeAppchain';

/// Computes the Starknet-OS-style config hash bound into v1 TEE report data.
///
/// `pedersen_array([KATANA_TEE_CONFIG_VERSION, chain_id, fee_token_address])`
///
/// The chained-Pedersen-with-length-suffix construction matches Cairo's
/// `compute_hash_on_elements` and Rust's `Pedersen::hash_array`, so the value
/// produced here is identical to the one Katana RPC binds into `report_data`
/// at quote-generation time.
pub fn compute_katana_tee_config_hash(
    chain_id: felt252, fee_token_address: ContractAddress,
) -> felt252 {
    let fee_token: felt252 = fee_token_address.into();
    pedersen_hash_on_elements(array![KATANA_TEE_CONFIG_VERSION, chain_id, fee_token].span())
}

/// Cairo equivalent of cairo-lang's `compute_hash_on_elements`: chained Pedersen
/// with a length suffix. Equivalent to Rust's `Pedersen::hash_array`.
fn pedersen_hash_on_elements(elements: Span<felt252>) -> felt252 {
    let mut state: felt252 = 0;
    let len: felt252 = elements.len().into();
    for el in elements {
        state = pedersen(state, *el);
    }
    pedersen(state, len)
}

#[cfg(test)]
mod tests {
    use super::{KATANA_TEE_CONFIG_VERSION, compute_katana_tee_config_hash, pedersen_hash_on_elements};

    /// Sanity-checks the `pedersen_hash_on_elements` chain against a known-good
    /// vector from upstream Starknet OS: hashing
    /// `[StarknetOsConfig3, MAINNET, STRK_FEE_TOKEN]` produces the public mainnet
    /// `starknet_os_config_hash`. Same hash function as `compute_katana_tee_config_hash`.
    #[test]
    fn pedersen_hash_on_elements_matches_mainnet_starknet_os_config_hash() {
        let starknet_os_config_v3: felt252 = 'StarknetOsConfig3';
        let mainnet_chain_id: felt252 = 0x534e5f4d41494e; // "SN_MAIN"
        let strk_fee_token: felt252 =
            0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d;
        let expected: felt252 =
            0x70c7b342f93155315d1cb2da7a4e13a3c2430f51fb5696c1b224c3da5508dfb;
        let computed = pedersen_hash_on_elements(
            array![starknet_os_config_v3, mainnet_chain_id, strk_fee_token].span(),
        );
        assert!(computed == expected);
    }

    /// `compute_katana_tee_config_hash` is deterministic and depends on both inputs.
    #[test]
    fn compute_katana_tee_config_hash_is_deterministic_and_input_dependent() {
        let chain_id: felt252 = 'KATANA';
        let fee_token: starknet::ContractAddress =
            0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d.try_into().unwrap();

        let h1 = compute_katana_tee_config_hash(chain_id, fee_token);
        let h2 = compute_katana_tee_config_hash(chain_id, fee_token);
        assert!(h1 == h2);
        assert!(h1 != 0);

        // Different chain_id must produce a different hash.
        let h_other_chain = compute_katana_tee_config_hash('SN_SEPOLIA', fee_token);
        assert!(h1 != h_other_chain);

        // Different fee_token must produce a different hash.
        let other_fee_token: starknet::ContractAddress = 0xdead.try_into().unwrap();
        let h_other_fee = compute_katana_tee_config_hash(chain_id, other_fee_token);
        assert!(h1 != h_other_fee);

        // Version tag is bound: hashing without it must differ.
        let fee_token_felt: felt252 = fee_token.into();
        let h_no_version = pedersen_hash_on_elements(array![chain_id, fee_token_felt].span());
        assert!(h1 != h_no_version);
        let _ = KATANA_TEE_CONFIG_VERSION; // keep constant referenced
    }
}

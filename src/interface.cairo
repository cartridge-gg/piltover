//! SPDX-License-Identifier: MIT
//!
//! Interface for appchain settlement contract.

use crate::input::component::PiltoverInput;

#[starknet::interface]
pub trait IAppchain<T> {
    /// Updates the state of the Appchain on Starknet,
    /// based on a proof of the StarknetOS that the state transition
    /// is valid.
    ///
    /// In the current state of the SN stack, the layout required by SNOS
    /// is not yet supported with the starknet onchain verifier (integrity).
    /// For this reason, two proofs are required:
    /// - A proof for SNOS execution.
    /// - A layout bridge proof, which uses a layout supported by the onchain verifier.
    ///
    /// Alternatively, a `TeeInput` can be used to settle state via an AMD TEE attestation
    /// rather than a ZK proof.
    ///
    /// # Important: `facts_registry` configuration
    ///
    /// The `facts_registry` address stored in config serves different purposes depending on
    /// the input variant:
    /// - `LayoutBridgeOutput*` — must point to an **Integrity fact registry** contract.
    /// - `TeeInput`            — must point to an **IAMDTeeRegistry** contract.
    ///
    /// Ensure the correct registry is configured before submitting each input type.
    ///
    /// # Arguments
    ///
    /// * `piltover_input` - The proof input: a layout bridge output (with or without DA) or a
    ///   TEE attestation input.
    fn update_state(ref self: T, piltover_input: PiltoverInput);
}

/// Owner-gated interface for resetting the settlement contract to a fresh genesis.
///
/// Intended for development workflows where an appchain is wiped back to genesis; the
/// settlement contract can be reset in place instead of redeployed. Guarded by owner-only
/// access (see the implementation). Note: on a production settlement deployment a reset
/// rewinds L1-tracked state and would enable message replay, so the owner key must be
/// treated accordingly.
#[starknet::interface]
pub trait IAppchainDev<T> {
    /// Resets the appchain settlement contract to a fresh genesis.
    ///
    /// Re-initializes the state checkpoint (`state_root` / `block_number` / `block_hash`)
    /// and zeroes the Starknet -> Appchain message nonce, while preserving the owner,
    /// operators, and program/registry configuration. This collapses a full
    /// redeploy-and-reconfigure into a single transaction when a developer wipes their
    /// appchain back to genesis.
    ///
    /// # Arguments
    ///
    /// * `state_root` - The genesis state root.
    /// * `block_number` - The genesis block number.
    /// * `block_hash` - The genesis block hash.
    fn reset_to_genesis(
        ref self: T, state_root: felt252, block_number: felt252, block_hash: felt252,
    );
}

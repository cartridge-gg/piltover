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

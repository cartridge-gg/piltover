//! SPDX-License-Identifier: MIT
//!
//! Interface for Appchain - Starknet state.
use piltover::input::layout_bridge::StateUpdateInput;

#[starknet::interface]
pub trait IState<T> {
    /// Gets the current state.
    ///
    /// # Returns
    ///
    /// The state root, the block number and the block hash.
    fn get_state(self: @T) -> (felt252, felt252, felt252);
}

#[starknet::interface]
pub trait IStateUpdater<T> {
    /// Validates that the 'blockNumber' and the previous root are consistent with the
    /// current state and updates the state.
    ///
    /// # Arguments
    ///
    /// * `input` - The state update input. Its made from either the output of the layout bridge or
    /// the TEE proof.
    fn update(ref self: T, input: StateUpdateInput);
}

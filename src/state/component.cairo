//! SPDX-License-Identifier: MIT
//!
//! Appchain - Starknet state component.

/// Errors.
mod errors {
    const INVALID_BLOCK_NUMBER: felt252 = 'State: invalid block number';
    const INVALID_PREVIOUS_ROOT: felt252 = 'State: invalid previous root';
}

/// State component.
#[starknet::component]
mod state_cpt {
    use core::iter::IntoIterator;
    use core::traits::TryInto;
    use piltover::snos_output::StarknetOsOutput;
    use piltover::snos_output::deserialize_os_output;
    use piltover::state::interface::IState;
    use super::errors;

    type StateRoot = felt252;
    type BlockNumber = i128;
    type BlockHash = felt252;

    #[storage]
    struct Storage {
        state_root: StateRoot,
        block_number: BlockNumber,
        block_hash: BlockHash,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {}

    #[embeddable_as(StateImpl)]
    impl State<
        TContractState, +HasComponent<TContractState>,
    > of IState<ComponentState<TContractState>> {
        fn update(ref self: ComponentState<TContractState>, program_output: StarknetOsOutput) {
            self.check_prev_block_number(@program_output);

            // Check the blockNumber first as the error is less ambiguous then
            // INVALID_PREVIOUS_ROOT.
            let new_block_number: i128 = program_output.new_block_number.try_into().unwrap();
            assert(new_block_number > self.block_number.read(), errors::INVALID_BLOCK_NUMBER);
            self.block_number.write(new_block_number);

            self.block_hash.write(program_output.new_block_hash);

            assert(
                self.state_root.read() == program_output.initial_root, errors::INVALID_PREVIOUS_ROOT
            );

            self.state_root.write(program_output.final_root);
        }

        fn get_state(self: @ComponentState<TContractState>) -> (StateRoot, BlockNumber, BlockHash) {
            (self.state_root.read(), self.block_number.read(), self.block_hash.read())
        }
    }

    #[generate_trait]
    impl InternalImpl<
        TContractState, +HasComponent<TContractState>,
    > of InternalTrait<TContractState> {
        /// Initialized the messaging component.
        /// # Arguments
        ///
        /// * `state_root` - The state root.
        /// * `block_number` - The current block number.
        /// * `block_hash` - The hash of the current block.
        fn initialize(
            ref self: ComponentState<TContractState>,
            state_root: StateRoot,
            block_number: BlockNumber,
            block_hash: BlockHash,
        ) {
            self.state_root.write(state_root);
            self.block_number.write(block_number);
            self.block_hash.write(block_hash);
        }

        ///  Validates that the previous block number that appears in the proof is the current block
        ///  number.
        fn check_prev_block_number(
            self: @ComponentState<TContractState>, program_output: @StarknetOsOutput
        ) {
            let mut expected_prev_block_number: felt252 = self.block_number.read().into();

            if self.block_number.read() == -1 {
                expected_prev_block_number =
                    0x800000000000011000000000000000000000000000000000000000000000000;
            }

            assert(
                expected_prev_block_number == *program_output.prev_block_number,
                errors::INVALID_BLOCK_NUMBER
            );
        }
    }
}

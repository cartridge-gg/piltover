//! SPDX-License-Identifier: MIT
//!
//! Mocks.

/// A fact registry mock to be used while Herodotus completes its implementation.
/// see : https://github.com/HerodotusDev/cairo-verifier/blob/keccak-fact-registry/

#[starknet::contract]
mod fact_registry_mock {
    use piltover::fact_registry::IFactRegistry;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl FactRegistryImplMock of IFactRegistry<ContractState> {
        fn is_valid(self: @ContractState, fact: felt252) -> bool {
            true
        }
    }
}

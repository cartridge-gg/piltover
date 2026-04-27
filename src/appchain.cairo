//! SPDX-License-Identifier: MIT
//!
//!

/// Appchain settlement contract on starknet.
#[starknet::contract]
pub mod appchain {
    use core::poseidon::PoseidonImpl;
    use integrity::Integrity;
    use openzeppelin::access::ownable::OwnableComponent as ownable_cpt;
    use openzeppelin::access::ownable::OwnableComponent::InternalTrait as OwnableInternal;
    use openzeppelin::security::reentrancyguard::ReentrancyGuardComponent;
    use openzeppelin::security::reentrancyguard::ReentrancyGuardComponent::InternalTrait as InternalReentrancyGuardImpl;
    use openzeppelin::upgrades::UpgradeableComponent as upgradeable_cpt;
    use openzeppelin::upgrades::UpgradeableComponent::InternalTrait as UpgradeableInternal;
    use openzeppelin::upgrades::interface::IUpgradeable;
    use piltover::components::onchain_data_fact_tree_encoder::{
        DataAvailabilityFact, encode_fact_with_onchain_data,
    };
    use piltover::config::config_cpt::InternalTrait as ConfigInternal;
    use piltover::config::{IConfig, config_cpt};
    use piltover::interface::IAppchain;
    use piltover::messaging::messaging_cpt;
    use piltover::messaging::messaging_cpt::InternalTrait as MessagingInternal;
    use piltover::state::state_cpt::InternalTrait as StateInternal;
    use piltover::state::{IStateUpdater, state_cpt};
    use starknet::storage::StoragePointerReadAccess;
    use starknet::{ClassHash, ContractAddress};
    use crate::input::component::{PiltoverInput, PiltoverInputTrait};
    use crate::input::katana_tee_config::compute_katana_tee_config_hash;

    /// The default cancellation delay of 5 days.
    const CANCELLATION_DELAY_SECS: u64 = 432000;


    component!(path: ownable_cpt, storage: ownable, event: OwnableEvent);
    component!(path: upgradeable_cpt, storage: upgradeable, event: UpgradeableEvent);
    component!(path: config_cpt, storage: config, event: ConfigEvent);
    component!(path: messaging_cpt, storage: messaging, event: MessagingEvent);
    component!(path: state_cpt, storage: state, event: StateEvent);
    component!(
        path: ReentrancyGuardComponent, storage: reentrancy_guard, event: ReentrancyGuardEvent,
    );

    #[abi(embed_v0)]
    impl ConfigImpl = config_cpt::ConfigImpl<ContractState>;
    #[abi(embed_v0)]
    impl MessagingImpl = messaging_cpt::MessagingImpl<ContractState>;
    #[abi(embed_v0)]
    impl StateImpl = state_cpt::StateImpl<ContractState>;

    #[abi(embed_v0)]
    impl OwnableImpl = ownable_cpt::OwnableTwoStepImpl<ContractState>;

    #[cfg(feature: 'messaging_test')]
    #[abi(embed_v0)]
    impl MessagingTestImpl =
        messaging_cpt::MessagingTestImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: ownable_cpt::Storage,
        #[substorage(v0)]
        upgradeable: upgradeable_cpt::Storage,
        #[substorage(v0)]
        config: config_cpt::Storage,
        #[substorage(v0)]
        messaging: messaging_cpt::Storage,
        #[substorage(v0)]
        reentrancy_guard: ReentrancyGuardComponent::Storage,
        #[substorage(v0)]
        state: state_cpt::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {
        #[flat]
        OwnableEvent: ownable_cpt::Event,
        #[flat]
        UpgradeableEvent: upgradeable_cpt::Event,
        #[flat]
        ConfigEvent: config_cpt::Event,
        #[flat]
        MessagingEvent: messaging_cpt::Event,
        #[flat]
        ReentrancyGuardEvent: ReentrancyGuardComponent::Event,
        #[flat]
        StateEvent: state_cpt::Event,
        LogStateUpdate: LogStateUpdate,
        LogStateUpdateWithDa: LogStateUpdateWithDa,
        LogStateTransitionFact: LogStateTransitionFact,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogStateUpdate {
        pub state_root: felt252,
        pub block_number: felt252,
        pub block_hash: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogStateUpdateWithDa {
        pub state_root: felt252,
        pub block_number: felt252,
        pub block_hash: felt252,
        pub da_layer_height: felt252,
        pub da_layer_commitment: felt252,
        pub da_layer_namespace: felt252,
    }

    #[derive(Drop, starknet::Event)]
    pub struct LogStateTransitionFact {
        pub state_transition_fact: u256,
    }

    /// Initializes the contract.
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address of the owner.
    /// * `state_root` - The state root of the contract.
    /// * `block_number` - The block number of the contract.
    /// * `block_hash` - The block hash of the contract.
    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        state_root: felt252,
        block_number: felt252,
        block_hash: felt252,
    ) {
        self.ownable.initializer(owner);
        self.messaging.initialize(CANCELLATION_DELAY_SECS);
        self.state.initialize(state_root, block_number, block_hash);
    }

    #[abi(embed_v0)]
    impl Appchain of IAppchain<ContractState> {
        fn update_state(ref self: ContractState, piltover_input: PiltoverInput) {
            self.reentrancy_guard.start();
            self.config.assert_only_owner_or_operator();

            let program_info = self.config.program_info.read();
            let expected_katana_tee_config_hash = compute_katana_tee_config_hash(
                self.config.get_chain_id(), self.config.get_fee_token_address(),
            );

            assert!(
                piltover_input
                    .validate_input(
                        program_info,
                        self.config.get_facts_registry(),
                        expected_katana_tee_config_hash,
                    ),
                "Input validation failed",
            );

            // Those values are currently not being used. They are enforced to 0 here
            // instead of being passed as arguments to avoid operator manipulation
            // until their usage is better defined.
            let data_availability_fact: DataAvailabilityFact = DataAvailabilityFact {
                onchain_data_hash: 0, onchain_data_size: 0,
            };
            // For LayoutBridge variants, get_raw_output() returns the bootloader output and
            // the resulting fact is meaningful to the Integrity verifier.
            // For TeeInput, get_raw_output() returns the raw SP1 proof bytes; the fact is
            // emitted purely as an audit trail and has no meaning to the Integrity verifier.
            let state_transition_fact: u256 = encode_fact_with_onchain_data(
                piltover_input.get_raw_output(), data_availability_fact,
            );

            self.emit(LogStateTransitionFact { state_transition_fact });

            self.state.update(piltover_input.get_state_update_input());

            let (messages_to_l1, messages_to_l2) = piltover_input.get_messages();
            self.messaging.process_messages_to_starknet(messages_to_l1);
            self.messaging.process_messages_to_appchain(messages_to_l2);

            self.reentrancy_guard.end();

            match piltover_input {
                PiltoverInput::LayoutBridgeOutputNoDa(_) => {
                    self
                        .emit(
                            LogStateUpdate {
                                state_root: self.state.state_root.read(),
                                block_number: self.state.block_number.read(),
                                block_hash: self.state.block_hash.read(),
                            },
                        );
                },
                PiltoverInput::LayoutBridgeOutputWithDa((
                    _, da_layer_info,
                )) => {
                    self
                        .emit(
                            LogStateUpdateWithDa {
                                state_root: self.state.state_root.read(),
                                block_number: self.state.block_number.read(),
                                block_hash: self.state.block_hash.read(),
                                da_layer_height: da_layer_info.height,
                                da_layer_commitment: da_layer_info.commitment,
                                da_layer_namespace: da_layer_info.namespace,
                            },
                        );
                },
                PiltoverInput::TeeInput(_) => {
                    self
                        .emit(
                            LogStateUpdate {
                                state_root: self.state.state_root.read(),
                                block_number: self.state.block_number.read(),
                                block_hash: self.state.block_hash.read(),
                            },
                        );
                },
            }
        }
    }

    #[abi(embed_v0)]
    impl UpgradeableImpl of IUpgradeable<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self.ownable.assert_only_owner();
            self.upgradeable.upgrade(new_class_hash);
        }
    }
}

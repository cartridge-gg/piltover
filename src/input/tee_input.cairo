use piltover::input::snos_output::{MessageToAppchain, MessageToStarknet};

#[derive(Drop, Serde, Debug)]
pub struct TEEInput {
    pub sp1_proof: Span<felt252>,
    pub prev_state_root: felt252,
    pub state_root: felt252,
    pub prev_block_hash: felt252,
    pub block_hash: felt252,
    pub prev_block_number: felt252,
    pub block_number: felt252,
    pub messages_commitment: felt252,
    pub messages_to_starknet: Span<MessageToStarknet>,
    pub messages_to_appchain: Span<MessageToAppchain>,
    /// keccak256 hashes (as felts) of each L1→L2 message, used to reconstruct
    /// `l1_to_l2_commitment` without recomputing keccak inside the contract.
    pub l1_to_l2_msg_hashes: Span<felt252>,
}


#[derive(Drop, Serde, Debug)]
pub struct TEEInput {
    pub sp1_proof: Span<felt252>,
    pub prev_state_root: felt252,
    pub state_root: felt252,
    pub prev_block_hash: felt252,
    pub block_hash: felt252,
    pub prev_block_number: felt252,
    pub block_number: felt252,
}


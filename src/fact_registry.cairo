use cairo_verifier::StarkProofWithSerde;
use starknet::ContractAddress;

#[starknet::interface]
trait IFactRegistry<TContractState> {
    fn is_valid(self: @TContractState, fact: felt252) -> bool;
}

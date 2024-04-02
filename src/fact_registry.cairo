use cairo_verifier::StarkProofWithSerde;
use starknet::ContractAddress;

#[starknet::interface]
trait IFactRegistry<TContractState> {
    fn verify_and_register_fact(ref self: TContractState, stark_proof: StarkProofWithSerde);
    fn verify_and_register_fact_from_contract(
        ref self: TContractState, contract_address: ContractAddress
    );
    fn is_valid(self: @TContractState, fact: felt252) -> bool;
}

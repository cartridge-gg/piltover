//! Mock implementation of `amd_tee_registry::IAMDTeeRegistry`.
//!
//! Used by end-to-end tests that want to exercise Piltover's TEE settlement
//! path without producing or verifying real AMD SEV-SNP attestations or SP1
//! Groth16 proofs. In mock mode, the off-chain caller (e.g. `saya-tee
//! --mock-prove`) builds the `sp1_proof` field of `TEEInput` as the
//! Cairo-Serde-serialized form of a `VerifierJournal` directly — bypassing
//! Garaga calldata entirely. This contract simply deserializes that input
//! back into a `VerifierJournal` and returns it without any cryptographic
//! checks.
//!
//! Piltover's `validate_input` for `TeeInput` only reads `journal.raw_report`
//! and `journal.result`, so callers can default the rest of the journal
//! fields. The `raw_report` field must contain a 296-word (1184-byte) buffer
//! whose `report_data` field at u32 offset 20 encodes
//! `Poseidon(prev_state_root, state_root, prev_block_hash, block_hash,
//!           prev_block_number, block_number, messages_commitment)` in the
//! limb layout that `RawAttestationReport::report_data()` produces.

#[starknet::contract]
pub mod mock_amd_tee_registry {
    use amd_tee_registry::tee_registry::IAMDTeeRegistry;
    use amd_tee_registry::tee_types::VerifierJournal;

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl MockImpl of IAMDTeeRegistry<ContractState> {
        fn verify_sp1_proof(
            ref self: ContractState, sp1_proof: Array<felt252>,
        ) -> Result<VerifierJournal, felt252> {
            let mut span = sp1_proof.span();
            match Serde::<VerifierJournal>::deserialize(ref span) {
                Option::Some(journal) => Result::Ok(journal),
                Option::None => Result::Err('mock: deserialize failed'),
            }
        }
    }
}

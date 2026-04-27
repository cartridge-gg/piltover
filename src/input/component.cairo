use VerificationResult::Success;
use amd_tee_registry::tee_registry::{IAMDTeeRegistryDispatcher, IAMDTeeRegistryDispatcherTrait};
use amd_tee_registry::tee_types::{
    RawAttestationReport, RawAttestationReportTrait, VerificationResult,
};
use core::integer::u128_byte_reverse;
use core::poseidon::poseidon_hash_span;
use integrity::Integrity;
use piltover::input::snos_output::{MessageToAppchain, MessageToStarknet};
use starknet::ContractAddress;
use crate::config::ProgramInfo;
use super::katana_tee_config::{KATANA_TEE_APPCHAIN_MODE, KATANA_TEE_REPORT_VERSION};
use super::layout_bridge::{DaLayerInfo, StateUpdateInput, deserialize_layout_bridge_output};
use super::tee_input::TEEInput;

mod errors {
    pub const INVALID_ADDRESS: felt252 = 'Config: invalid address';
    pub const SNOS_INVALID_PROGRAM_OUTPUT_SIZE: felt252 = 'snos: invalid output size';
    pub const SNOS_INVALID_OUTPUT_HASH: felt252 = 'snos: invalid output hash';
    pub const SNOS_INVALID_PROGRAM_HASH: felt252 = 'snos: invalid program hash';
    pub const SNOS_INVALID_CONFIG_HASH: felt252 = 'snos: invalid config hash';
    pub const SNOS_INVALID_MESSAGES_SEGMENTS: felt252 = 'snos: invalid messages segments';
    pub const NO_STATE_TRANSITION_PROOF: felt252 = 'no state transition proof';
    pub const NO_FACT_REGISTERED: felt252 = 'no fact registered';
    pub const LAYOUT_BRIDGE_INVALID_PROGRAM_HASH: felt252 = 'lb: invalid program hash';
    pub const LAYOUT_BRIDGE_INVALID_BOOTLOADER_HASH: felt252 = 'lb: invalid bootloader hash';
    pub const TEE_INVALID_CONFIG_HASH: felt252 = 'tee: invalid config hash';
    pub const TEE_REPORT_DATA_MISMATCH: felt252 = 'tee: report data mismatch';
    pub const TEE_CONFIG_HASH_HALF_MISMATCH: felt252 = 'tee: config hash half mismatch';
    pub const TEE_INVALID_MESSAGES: felt252 = 'tee: invalid messages';
    pub const TEE_SP1_PROOF_FAILED: felt252 = 'tee: sp1 proof failed';
}

/// The minimum security bits required for a fact to be considered valid.
const MIN_SECURITY_BITS: u32 = 50;

#[derive(Drop, Serde, Debug)]
pub enum PiltoverInput {
    LayoutBridgeOutputNoDa: Span<felt252>,
    LayoutBridgeOutputWithDa: (Span<felt252>, DaLayerInfo),
    TeeInput: TEEInput,
}

fn lb_output_to_state_update_input(lb_output: Span<felt252>) -> StateUpdateInput {
    let snos = deserialize_layout_bridge_output(lb_output).bootloader_output.snos_output;
    StateUpdateInput {
        prev_state_root: snos.initial_root,
        state_root: snos.final_root,
        prev_block_number: snos.prev_block_number,
        block_number: snos.new_block_number,
        prev_block_hash: snos.prev_block_hash,
        block_hash: snos.new_block_hash,
    }
}

fn validate_lb_output(
    lb_output: Span<felt252>, program_info: ProgramInfo, fact_registry_address: ContractAddress,
) -> bool {
    let lb = deserialize_layout_bridge_output(lb_output);
    assert(
        program_info.snos_program_hash == lb.bootloader_output.snos_program_hash,
        errors::SNOS_INVALID_PROGRAM_HASH,
    );
    assert(
        program_info.layout_bridge_program_hash == lb.layout_bridge_program_hash,
        errors::LAYOUT_BRIDGE_INVALID_PROGRAM_HASH,
    );
    assert(
        program_info.bootloader_program_hash == lb.bootloader_program_hash,
        errors::LAYOUT_BRIDGE_INVALID_BOOTLOADER_HASH,
    );
    let program_output_struct = lb.bootloader_output.snos_output;
    assert(
        program_output_struct.starknet_os_config_hash == program_info.snos_config_hash,
        errors::SNOS_INVALID_CONFIG_HASH,
    );

    let output_hash = poseidon_hash_span(lb_output);
    let fact = poseidon_hash_span(array![program_info.bootloader_program_hash, output_hash].span());
    let integrity = Integrity::from_address(fact_registry_address);
    assert(
        integrity.is_fact_hash_valid_with_security(fact, MIN_SECURITY_BITS),
        errors::NO_FACT_REGISTERED,
    );
    true
}

pub trait PiltoverInputTrait {
    fn get_raw_output(
        self: @PiltoverInput,
    ) -> Span<
        felt252,
    > {
        match self {
            PiltoverInput::LayoutBridgeOutputNoDa(lb_output) => *lb_output,
            PiltoverInput::LayoutBridgeOutputWithDa((lb_output, _)) => *lb_output,
            PiltoverInput::TeeInput(tee_input) => *tee_input.sp1_proof,
        }
    }
    /// Validates the input based on its type.
    ///
    /// For `LayoutBridgeOutput*` variants, `fact_registry_address` must point to an Integrity
    /// fact registry contract, and `program_info` is used to verify program hashes.
    /// `expected_katana_tee_config_hash` is unused on these variants.
    ///
    /// For `TeeInput`, `fact_registry_address` must point to an `IAMDTeeRegistry` contract
    /// and `expected_katana_tee_config_hash` must be the v1 config hash recomputed from
    /// the Piltover config (chain id + fee token). `program_info` is unused on this variant.
    fn validate_input(
        self: @PiltoverInput,
        program_info: ProgramInfo,
        fact_registry_address: ContractAddress,
        expected_katana_tee_config_hash: felt252,
    ) -> bool {
        match self {
            PiltoverInput::LayoutBridgeOutputNoDa(lb_output) => {
                validate_lb_output(*lb_output, program_info, fact_registry_address)
            },
            PiltoverInput::LayoutBridgeOutputWithDa((
                lb_output, _,
            )) => { validate_lb_output(*lb_output, program_info, fact_registry_address) },
            PiltoverInput::TeeInput(tee_input) => {
                // 1. Environment binding: the attested config hash must match the
                //    Piltover-side expected hash (recomputed from chain id + fee token).
                //    Rejects attestations from any other appchain configuration.
                assert!(
                    *tee_input.katana_tee_config_hash == expected_katana_tee_config_hash,
                    "{}",
                    errors::TEE_INVALID_CONFIG_HASH,
                );

                // 2. SP1 proof verification + raw report extraction.
                let registry = IAMDTeeRegistryDispatcher {
                    contract_address: fact_registry_address,
                };
                let sp1_proof = *tee_input.sp1_proof;
                let journal = registry.verify_sp1_proof(sp1_proof.into()).unwrap();
                let raw_report = RawAttestationReport { raw: journal.raw_report };
                let report_data = raw_report.report_data();

                // 3. Decode `report_data` (u512) as two big-endian 32-byte halves.
                //    First half = v1 commitment (felt252).
                //    Second half = config hash (felt252), exposed for direct inspection.
                //    Each 32-byte half is two u128 limbs in big-endian order; byte-reversing
                //    each limb converts to little-endian for u256 / felt252 comparison.
                let attested_commitment = u256 {
                    low: u128_byte_reverse(report_data.limb1),
                    high: u128_byte_reverse(report_data.limb0),
                };
                let attested_config_hash = u256 {
                    low: u128_byte_reverse(report_data.limb3),
                    high: u128_byte_reverse(report_data.limb2),
                };

                // 4. Second-half config hash must equal the input config hash.
                //    Catches the failure mode where someone attests to a different config
                //    in the second half but constructs a matching first-half commitment.
                assert!(
                    attested_config_hash == (*tee_input.katana_tee_config_hash).into(),
                    "{}",
                    errors::TEE_CONFIG_HASH_HALF_MISMATCH,
                );

                // 5. Recompute the v1 commitment from the input fields and assert it matches
                //    the attested first half. v1 schema:
                //      Poseidon([
                //        KATANA_TEE_REPORT_VERSION,
                //        KATANA_TEE_APPCHAIN_MODE,
                //        prev_state_root, state_root,
                //        prev_block_hash, block_hash,
                //        prev_block_number, block_number,
                //        messages_commitment,
                //        katana_tee_config_hash,
                //      ])
                let commitment = poseidon_hash_span(
                    array![
                        KATANA_TEE_REPORT_VERSION, KATANA_TEE_APPCHAIN_MODE,
                        *tee_input.prev_state_root, *tee_input.state_root,
                        *tee_input.prev_block_hash, *tee_input.block_hash,
                        *tee_input.prev_block_number, *tee_input.block_number,
                        *tee_input.messages_commitment, *tee_input.katana_tee_config_hash,
                    ]
                        .span(),
                );
                assert!(
                    attested_commitment == commitment.into(),
                    "{}",
                    errors::TEE_REPORT_DATA_MISMATCH,
                );

                assert!(journal.result == Success, "{}", errors::TEE_SP1_PROOF_FAILED);

                // 6. Verify messages_commitment matches the provided message data.
                //    l2_to_l1: recompute Poseidon hash for each MessageToStarknet.
                let mut l2_to_l1_hashes: Array<felt252> = array![];
                for msg in *tee_input.messages_to_starknet {
                    let payload_hash = poseidon_hash_span(
                        {
                            let mut v: Array<felt252> = array![(*msg.payload).len().into()];
                            for p in *msg.payload {
                                v.append(*p);
                            }
                            v.span()
                        },
                    );
                    l2_to_l1_hashes
                        .append(
                            poseidon_hash_span(
                                array![
                                    (*msg.from_address).into(), (*msg.to_address).into(),
                                    payload_hash,
                                ]
                                    .span(),
                            ),
                        );
                }
                let l2_to_l1_commitment = poseidon_hash_span(l2_to_l1_hashes.span());
                let l1_to_l2_commitment = poseidon_hash_span(*tee_input.l1_to_l2_msg_hashes);
                let expected_messages_commitment = poseidon_hash_span(
                    array![l2_to_l1_commitment, l1_to_l2_commitment].span(),
                );
                assert!(
                    expected_messages_commitment == *tee_input.messages_commitment,
                    "{}",
                    errors::TEE_INVALID_MESSAGES,
                );

                true
            },
        }
    }
    fn get_state_update_input(
        self: @PiltoverInput,
    ) -> StateUpdateInput {
        match self {
            PiltoverInput::TeeInput(tee_input) => StateUpdateInput {
                prev_state_root: *tee_input.prev_state_root,
                state_root: *tee_input.state_root,
                prev_block_number: *tee_input.prev_block_number,
                block_number: *tee_input.block_number,
                prev_block_hash: *tee_input.prev_block_hash,
                block_hash: *tee_input.block_hash,
            },
            PiltoverInput::LayoutBridgeOutputNoDa(lb_output) => {
                lb_output_to_state_update_input(*lb_output)
            },
            PiltoverInput::LayoutBridgeOutputWithDa((
                lb_output, _,
            )) => { lb_output_to_state_update_input(*lb_output) },
        }
    }
    fn get_messages(
        self: @PiltoverInput,
    ) -> (
        Span<MessageToStarknet>, Span<MessageToAppchain>,
    ) {
        match self {
            PiltoverInput::TeeInput(tee_input) => {
                (*tee_input.messages_to_starknet, *tee_input.messages_to_appchain)
            },
            PiltoverInput::LayoutBridgeOutputNoDa(lb_output) => {
                let snos = deserialize_layout_bridge_output(*lb_output)
                    .bootloader_output
                    .snos_output;
                (snos.messages_to_l1, snos.messages_to_l2)
            },
            PiltoverInput::LayoutBridgeOutputWithDa((
                lb_output, _,
            )) => {
                let snos = deserialize_layout_bridge_output(*lb_output)
                    .bootloader_output
                    .snos_output;
                (snos.messages_to_l1, snos.messages_to_l2)
            },
        }
    }
}

impl PiltoverInputImpl of PiltoverInputTrait {
    fn get_raw_output(self: @PiltoverInput) -> Span<felt252> {
        match self {
            PiltoverInput::LayoutBridgeOutputNoDa(lb_output) => *lb_output,
            PiltoverInput::LayoutBridgeOutputWithDa((lb_output, _)) => *lb_output,
            PiltoverInput::TeeInput(tee_input) => *tee_input.sp1_proof,
        }
    }
}

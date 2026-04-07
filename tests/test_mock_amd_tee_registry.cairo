//! Tests for `piltover::input::mock_amd_tee_registry`.
//!
//! Verifies that the mock contract round-trips a `VerifierJournal` through
//! its `verify_sp1_proof` entry point: a journal serialized via Cairo Serde
//! into the `sp1_proof: Array<felt252>` argument is returned bit-for-bit
//! intact, with no on-chain verification of the underlying SP1 Groth16 proof
//! or AMD attestation report.

use amd_tee_registry::tee_registry::{
    IAMDTeeRegistryDispatcher, IAMDTeeRegistryDispatcherTrait,
};
use amd_tee_registry::tee_types::{VerificationResult, VerifierJournal};
use snforge_std as snf;
use snforge_std::ContractClassTrait;
use starknet::SyscallResultTrait;

/// Deploys the mock AMD TEE registry contract and returns a dispatcher.
fn deploy_mock_amd_tee_registry() -> IAMDTeeRegistryDispatcher {
    let contract = match snf::declare("mock_amd_tee_registry").unwrap_syscall() {
        snf::DeclareResult::Success(contract) => contract,
        _ => core::panic_with_felt252('AlreadyDeclared not expected'),
    };
    let (contract_address, _) = contract.deploy(@array![]).unwrap_syscall();
    IAMDTeeRegistryDispatcher { contract_address }
}

/// Builds a `VerifierJournal` whose `raw_report` field has the canonical
/// 296-word (1184-byte) length expected by `RawAttestationReport`. All
/// fields are filled with deterministic, recognisable values so the
/// round-trip assertion below is meaningful.
fn make_journal() -> VerifierJournal {
    let mut raw_report: Array<u32> = array![];
    let mut i: u32 = 0;
    while i < 296 {
        raw_report.append(i);
        i += 1;
    }

    VerifierJournal {
        result: VerificationResult::Success,
        timestamp: 1_700_000_000,
        processor_model: 0,
        raw_report: raw_report.span(),
        certs: array![],
        cert_serials: array![],
        trusted_certs_prefix_len: 1,
        storage_commitment: 0,
        fork_block_number: 0,
        end_block_number: 0,
    }
}

#[test]
fn test_mock_round_trips_journal() {
    let registry = deploy_mock_amd_tee_registry();
    let journal_in = make_journal();

    let mut sp1_proof: Array<felt252> = array![];
    Serde::<VerifierJournal>::serialize(@journal_in, ref sp1_proof);

    let journal_out = registry.verify_sp1_proof(sp1_proof).expect('verify_sp1_proof failed');

    assert!(journal_out == journal_in, "round-tripped journal does not match input");
}

#[test]
fn test_mock_rejects_garbage() {
    let registry = deploy_mock_amd_tee_registry();
    // A short felt array that cannot deserialize into a VerifierJournal.
    let sp1_proof: Array<felt252> = array![1, 2, 3];
    match registry.verify_sp1_proof(sp1_proof) {
        Result::Ok(_) => core::panic_with_felt252('expected error'),
        Result::Err(e) => assert!(e == 'mock: deserialize failed', "wrong error: {}", e),
    }
}

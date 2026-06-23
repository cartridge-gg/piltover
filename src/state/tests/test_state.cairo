use piltover::input::layout_bridge::StateUpdateInput;
use piltover::state::{
    IStateDispatcher, IStateDispatcherTrait, IStateUpdaterDispatcher, IStateUpdaterDispatcherTrait,
};
use snforge_std as snf;
use snforge_std::ContractClassTrait;
use starknet::SyscallResultTrait;

/// Deploys the mock with a specific state.
fn deploy_mock_with_state(
    state_root: felt252, block_number: felt252, block_hash: felt252,
) -> IStateDispatcher {
    let contract = match snf::declare("state_mock").unwrap_syscall() {
        snf::DeclareResult::Success(contract) => contract,
        _ => core::panic_with_felt252('AlreadyDeclared not expected'),
    };
    let calldata = array![state_root, block_number, block_hash];
    let (contract_address, _) = contract.deploy(@calldata).unwrap_syscall();
    IStateDispatcher { contract_address }
}

#[test]
fn state_update_ok() {
    let mock = deploy_mock_with_state(state_root: 1, block_number: 1, block_hash: 1);
    let state_update = StateUpdateInput {
        prev_state_root: 1,
        state_root: 2,
        prev_block_number: 1,
        block_number: 2,
        prev_block_hash: 1,
        block_hash: 2,
    };

    let updater = IStateUpdaterDispatcher { contract_address: mock.contract_address };
    updater.update(state_update);

    let (state_root, block_number, block_hash) = mock.get_state();

    assert(state_root == 2, 'invalid state root');
    assert(block_number == 2, 'invalid block number');
    assert(block_hash == 2, 'invalid block hash');
}

#[test]
fn genesis_state_update_ok() {
    let max_felt = 0x800000000000011000000000000000000000000000000000000000000000000;
    let mock = deploy_mock_with_state(state_root: 0, block_number: max_felt, block_hash: 0);
    let state_update = StateUpdateInput {
        prev_state_root: 0,
        state_root: 1,
        prev_block_number: max_felt,
        block_number: 0,
        prev_block_hash: 0,
        block_hash: 1,
    };

    let updater = IStateUpdaterDispatcher { contract_address: mock.contract_address };

    updater.update(state_update);

    let (state_root, block_number, block_hash) = mock.get_state();

    assert(state_root == 1, 'invalid state root');
    assert(block_number == 0, 'invalid block number');
    assert(block_hash == 1, 'invalid block hash');
}

#[test]
#[should_panic(expected: ('State: invalid block number',))]
fn state_update_invalid_block_number() {
    let mock = deploy_mock_with_state(state_root: 1, block_number: 1, block_hash: 1);

    let state_update = StateUpdateInput {
        prev_state_root: 1,
        state_root: 2,
        prev_block_number: 5,
        block_number: 'invalid_block_number',
        prev_block_hash: 1,
        block_hash: 2,
    };

    let updater = IStateUpdaterDispatcher { contract_address: mock.contract_address };
    updater.update(state_update);
}

#[test]
#[should_panic(expected: ('State: invalid previous root',))]
fn state_update_invalid_previous_root() {
    let mock = deploy_mock_with_state(state_root: 1, block_number: 1, block_hash: 1);

    let invalid_state_update = StateUpdateInput {
        prev_state_root: 'invalid_previous_root',
        state_root: 2,
        prev_block_number: 1,
        block_number: 2,
        prev_block_hash: 1,
        block_hash: 2,
    };

    let updater = IStateUpdaterDispatcher { contract_address: mock.contract_address };
    updater.update(invalid_state_update);
}

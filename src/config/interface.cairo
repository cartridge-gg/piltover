//! SPDX-License-Identifier: MIT
//!
//! Interface for appchain settlement contract configuration.
use starknet::ContractAddress;

/// Program info for validity-proof (StarknetOS + Layout Bridge) settlement.
///
/// The StarknetOS (SNOS) is executed and proven first. Since the layout used by
/// SNOS is not verifiable onchain, a bridge layout program is also executed on
/// the proof generated from SNOS execution. Since the Layout Bridge program is
/// bootloaded, the bootloader program hash is also included, as the fact
/// registered in the facts registry is computed from the Layout Bridge program
/// hash and its output.
///
/// The four hashes together pin the SNOS execution environment.
#[derive(starknet::Store, Drop, Serde, Copy, PartialEq)]
pub struct StarknetOsProgramInfo {
    /// The hash of the bootloader program that bootloads the Layout Bridge program.
    pub bootloader_program_hash: felt252,
    /// The hash of the SNOS config:
    /// https://github.com/starkware-libs/cairo-lang/blob/a86e92bfde9c171c0856d7b46580c66e004922f3/src/starkware/starknet/core/os/os_config/os_config.cairo#L1-L39
    pub snos_config_hash: felt252,
    /// The hash of the SNOS program.
    pub snos_program_hash: felt252,
    /// The hash of the Layout Bridge program.
    pub layout_bridge_program_hash: felt252,
}

/// Program info for Katana TEE settlement.
///
/// In TEE mode, the appchain is identified entirely by a single versioned
/// environment config hash bound into the SEV-SNP `report_data`. Program hashes
/// are irrelevant; the TEE attestation pins the off-chain Katana node, not a
/// Cairo program.
#[derive(starknet::Store, Drop, Serde, Copy, PartialEq)]
pub struct KatanaTeeProgramInfo {
    /// Versioned environment config hash bound into v1 TEE attestations.
    /// Computed off-chain by the Katana node:
    /// `pedersen_array([KatanaTeeConfig1, chain_id, fee_token_address])`.
    /// The on-chain side stores it and compares against the attested value;
    /// it does not recompute.
    pub katana_tee_config_hash: felt252,
}

/// Information of the program verified onchain to apply the state transition.
///
/// Each Piltover deployment commits to one settlement mode at config time. The
/// `PiltoverInput` variant submitted to `update_state` must agree with the
/// active `ProgramInfo` variant or the call panics.
#[derive(starknet::Store, Drop, Serde, Copy, PartialEq)]
pub enum ProgramInfo {
    /// Default variant: an all-zero `StarknetOsProgramInfo` is what fresh storage
    /// returns before `set_program_info` is called. This preserves the original
    /// semantics from when `ProgramInfo` was a single struct of zeroed felts.
    #[default]
    StarknetOs: StarknetOsProgramInfo,
    KatanaTee: KatanaTeeProgramInfo,
}

#[starknet::interface]
pub trait IConfig<T> {
    /// Registers an operator that is in charge to push state updates.
    /// Multiple operators can be registered.
    /// # Arguments
    ///
    /// * `address` - The account address to register as an operator.
    fn register_operator(ref self: T, address: ContractAddress);

    /// Unregisters an operator.
    /// # Arguments
    ///
    /// * `address` - The operator account address to unregister.
    fn unregister_operator(ref self: T, address: ContractAddress);

    /// Verifies if the given address is an operator.
    /// # Arguments
    ///
    /// * `address` - The address to verify.
    ///
    /// # Returns
    ///
    /// True if the address is an operator, false otherwise.
    fn is_operator(self: @T, address: ContractAddress) -> bool;

    /// Sets the information of the program verified onchain to
    /// execute the state transition.
    ///
    /// # Arguments
    ///
    /// * `program_info` - The program information.
    fn set_program_info(ref self: T, program_info: ProgramInfo);

    /// Gets the information of the program verified onchain to
    /// execute the state transition.
    ///
    /// # Returns
    ///
    /// The program information.
    fn get_program_info(self: @T) -> ProgramInfo;

    /// Sets the facts registry contract address, which is already
    /// initialized with the verifier information.
    ///
    /// # Arguments
    ///
    /// * `address` - The facts registry contract's address.
    fn set_facts_registry(ref self: T, address: ContractAddress);

    /// Gets the facts registry contract address.
    ///
    /// # Returns
    ///
    /// The contract address of the facts registry.
    fn get_facts_registry(self: @T) -> ContractAddress;

    /// Sets if KZG DA is enabled.
    ///
    /// # Arguments
    ///
    /// * `use_kzg_da` - Whether KZG DA is enabled.
    fn set_use_kzg_da(ref self: T, use_kzg_da: bool);

    /// Gets if KZG DA is enabled.
    ///
    /// # Returns
    ///
    /// Whether KZG DA is enabled.
    fn get_use_kzg_da(self: @T) -> bool;
}

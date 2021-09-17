// ! Runtime API definition required by threshold_signature RPC extensions.
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments, clippy::unnecessary_mut_passed)]
pub use pallet_threshold_signature::primitive::{Message, Pubkey, Signature};
use sp_runtime::{AccountId32, DispatchError};
use sp_std::vec::Vec;

sp_api::decl_runtime_apis! {
    pub trait ThresholdSignatureApi
    {
        fn verify_threshold_signature(
            addr: AccountId32,
            signature: Signature,
            pubkey: Pubkey,
            control_block: Vec<Vec<u8>>,
            message: Message,
        ) -> Result<bool, DispatchError>;
    }
}

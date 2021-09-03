#![cfg_attr(not(feature = "std"), no_std)]
//Exported dependencies.
#[macro_use]
pub extern crate bitcoin_hashes as hashes;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
extern crate core2;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

mod mast;
#[cfg(test)]
mod mock;
pub mod primitive;
#[cfg(test)]
mod tests;
mod types;
pub mod weights;

use self::weights::WeightInfo;
use self::{
    mast::{try_to_bench32m, tweak_pubkey, Mast, XOnly},
    primitive::{Addr, Message, Script, Signature},
};
use frame_support::{dispatch::DispatchError, inherent::Vec};
use mast::{tagged_branch, ScriptMerkleNode};
pub use pallet::*;
use schnorrkel::{signing_context, PublicKey, Signature as SchnorrSignature};
use sp_core::sp_std::convert::TryFrom;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use frame_support::{dispatch::DispatchResult, pallet_prelude::*};
    use frame_system::pallet_prelude::*;

    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }
    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn addr_to_script)]
    pub type AddrToScript<T: Config> = StorageMap<_, Twox64Concat, Addr, Vec<Script>, ValueQuery>;

    #[pallet::event]
    #[pallet::metadata(T::AccountId = "AccountId")]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Submit scripts to generate address. [addr]
        GenerateAddress(Vec<u8>),
        /// Verify threshold signature
        VerifySignature,
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        /// No address in storage, generate address first
        NoAddressInStorage,
        /// Building Mast error
        MastBuildError,
        /// The constructed MAST is incorrect.
        /// NOTE: General error, may need to be optimized
        InvalidMast,
        /// Error from mast generate Merkle proof
        MastGenProofError,
        /// Error from mast generate address
        MastGenAddrError,
        /// Invalid Encoding,
        InvalidEncoding,
        /// Signature verification failure
        InvalidSignature,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Generate threshold signature address according to the script provided by the user.
        #[pallet::weight(<T as Config>::WeightInfo::generate_address())]
        pub fn generate_address(origin: OriginFor<T>, scripts: Vec<Vec<u8>>) -> DispatchResult {
            ensure_signed(origin)?;
            let addr = Self::apply_generate_address(scripts)?;
            Self::deposit_event(Event::GenerateAddress(addr));
            Ok(())
        }

        #[pallet::weight(<T as Config>::WeightInfo::verify_threshold_signature())]
        pub fn verify_threshold_signature(
            origin: OriginFor<T>,
            addr: Vec<u8>,
            signature: Vec<u8>,
            script: Vec<u8>,
            message: Vec<u8>,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::apply_verify_threshold_signature(addr, signature, script, message)?;
            Self::deposit_event(Event::VerifySignature);
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    fn apply_generate_address(scripts: Vec<Script>) -> Result<Addr, DispatchError> {
        let script_nodes = scripts
            .iter()
            .map(|script| XOnly::try_from(script.clone()))
            .collect::<Result<Vec<XOnly>, _>>()
            .map_err::<Error<T>, _>(Into::into)?;

        let mast = Mast::new(Vec::from(&script_nodes[1..]));
        let addr = mast
            .generate_address(&script_nodes[0])
            .map_err::<Error<T>, _>(Into::into)?;

        AddrToScript::<T>::insert(Vec::from(addr.clone()), scripts);
        Ok(Vec::from(addr))
    }

    pub fn apply_verify_threshold_signature(
        addr: Addr,
        signature: Signature,
        full_script: Script,
        message: Message,
    ) -> Result<bool, DispatchError> {
        // make sure the address has its corresponding scripts
        if !AddrToScript::<T>::contains_key(addr.clone()) {
            return Err(Error::<T>::NoAddressInStorage.into());
        }

        let scripts = AddrToScript::<T>::get(&addr);

        // convert script code into leaf nodes of MAST
        let script_nodes = scripts
            .iter()
            .map(|script| XOnly::try_from(script.clone()))
            .collect::<Result<Vec<XOnly>, _>>()
            .map_err::<Error<T>, _>(Into::into)?;

        // construct the MAST tree and skip the first one, which is actually the internal public key
        let mast = Mast::new(Vec::from(&script_nodes[1..]));
        let exec_script =
            XOnly::try_from(full_script.clone()).map_err::<Error<T>, _>(Into::into)?;
        // construct the merkel proof for the script to be executed
        let proof = mast
            .generate_merkle_proof(&exec_script)
            .map_err::<Error<T>, _>(Into::into)?;

        Self::verify_proof(addr, &proof, script_nodes)?;
        Self::verify_signature(signature, full_script, message)?;

        Ok(true)
    }

    /// To verify proof
    ///
    /// if the proof contains an executing script, the merkel root is calculated from here
    fn verify_proof(
        addr: Addr,
        proof: &[ScriptMerkleNode],
        scripts: Vec<XOnly>,
    ) -> Result<(), Error<T>> {
        // the currently executing script
        let mut exec_script_node = proof[0];
        // compute merkel root
        for node in proof.iter().skip(1) {
            exec_script_node = tagged_branch(exec_script_node, *node)?;
        }
        let merkel_root = exec_script_node;
        // calculate the output address using the internal public key and the script root
        let tweaked = &tweak_pubkey(&scripts[0], &merkel_root)?;
        let output_address = try_to_bench32m(tweaked)?;

        // ensure that the final computed public key is the same as
        // the public key of the address in the output
        if addr != Vec::from(output_address) {
            return Err(Error::<T>::MastGenProofError);
        }

        Ok(())
    }

    // To verify schnorr signature
    fn verify_signature(
        signature: Signature,
        script: Script,
        message: Message,
    ) -> Result<(), Error<T>> {
        let sig = SchnorrSignature::from_bytes(signature.as_slice())?;

        let agg_pubkey = PublicKey::from_bytes(&script)?;
        let ctx = signing_context(b"multi-sig");

        if agg_pubkey.verify(ctx.bytes(&message), &sig).is_err() {
            return Err(Error::<T>::InvalidSignature);
        }

        Ok(())
    }
}

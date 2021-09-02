#![cfg_attr(not(feature = "std"), no_std)]
//Exported dependencies.
#[macro_use]
pub extern crate bitcoin_hashes as hashes;

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
extern crate core2;

mod mast;
#[cfg(test)]
mod mock;
mod primitive;
#[cfg(test)]
mod tests;
mod types;

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
        GenerateAddress(Addr),
        /// Verify threshold signature
        VerifySignature,
    }

    // Errors inform users that something went wrong.
    #[pallet::error]
    pub enum Error<T> {
        /// Address not exist
        AddrNotExist,
        /// Error format of scripts
        ScriptFormatError,
        /// Error from mast generate Merkle proof
        MastGenMerProofError,
        /// Error from mast generate address
        MastGenAddrError,
        /// The constructed MAST is incorrect.
        /// NOTE: General error, may need to be optimized
        BadMast,
        /// Signature verification failure
        InvalidSignature,
        /// XOnly Invalid length
        XOnlyInvalidLength,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Generate threshold signature address according to the script provided by the user.
        #[pallet::weight(10_000 + T::DbWeight::get().writes(1))]
        pub fn generate_address(origin: OriginFor<T>, scripts: Vec<Script>) -> DispatchResult {
            ensure_signed(origin)?;
            let addr = Self::apply_generate_address(scripts)?;
            Self::deposit_event(Event::GenerateAddress(addr));
            Ok(())
        }

        #[pallet::weight(10_000 + T::DbWeight::get().reads(1))]
        pub fn verify_threshold_signature(
            origin: OriginFor<T>,
            addr: Addr,
            signature: Signature,
            script: Script,
            message: Message,
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
        let s = scripts
            .iter()
            .map(|script| XOnly::try_from(script.clone()))
            .collect::<Result<Vec<XOnly>, _>>()
            .map_err::<Error<T>, _>(Into::into)?;

        let mast = Mast::new(Vec::from(&s[1..]));
        let addr = mast
            .generate_address(&s[0])
            .map_err::<Error<T>, _>(Into::into)?;

        AddrToScript::<T>::insert(Vec::from(addr.clone()), scripts);
        Ok(Vec::from(addr))
    }

    fn apply_verify_threshold_signature(
        addr: Addr,
        signature: Signature,
        full_script: Script,
        message: Message,
    ) -> Result<bool, DispatchError> {
        if !AddrToScript::<T>::contains_key(addr.clone()) {
            return Err(Error::<T>::AddrNotExist.into());
        }

        let scripts = AddrToScript::<T>::get(&addr);
        // TODO: Optimize the name of variable
        let s = scripts
            .iter()
            .map(|script| XOnly::try_from(script.clone()))
            .collect::<Result<Vec<XOnly>, _>>()
            .map_err::<Error<T>, _>(Into::into)?;

        let mast = Mast::new(Vec::from(&s[1..]));
        let s1 = XOnly::try_from(full_script.clone()).map_err::<Error<T>, _>(Into::into)?;

        let proof = mast
            .generate_merkle_proof(&s1)
            .map_err::<Error<T>, _>(Into::into)?;

        Self::verify_proof(addr, &proof, s)?;
        Self::verify_signature(signature, full_script, message)?;

        Ok(true)
    }

    // to verify proof
    //
    // if the proof contains an executing script, the merkel root is calculated from here
    fn verify_proof(addr: Addr, proof: &[ScriptMerkleNode], s: Vec<XOnly>) -> Result<(), Error<T>> {
        let mut exec_script = proof[0];
        // compute merkel root
        for i in proof.iter().skip(1) {
            exec_script = tagged_branch(exec_script, *i)?;
        }

        let tweaked = try_to_bench32m(&tweak_pubkey(&s[0], &exec_script))?;

        // ensure that the final computed public key is the same as
        // the public key of the address in the output
        if addr != Vec::from(tweaked) {
            return Err(Error::<T>::MastGenMerProofError);
        }

        Ok(())
    }

    // To verify signature
    fn verify_signature(
        signature: Signature,
        script: Script,
        message: Message,
    ) -> Result<(), Error<T>> {
        let sig = SchnorrSignature::from_bytes(signature.as_slice())?;

        let agg_pubkey = PublicKey::from_bytes(&script).unwrap();
        let ctx = signing_context(b"multi-sig");

        if agg_pubkey.verify(ctx.bytes(&message), &sig).is_err() {
            return Err(Error::<T>::InvalidSignature);
        }

        Ok(())
    }
}

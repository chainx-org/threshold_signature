#![cfg_attr(not(feature = "std"), no_std)]

use core::slice::SlicePattern;

use mast::tagged_branch;
pub use pallet::*;

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

#[cfg(test)]
mod tests;

mod primitive;

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

use frame_support::{dispatch::DispatchError, inherent::Vec};
use schnorrkel::{signing_context, PublicKey, Signature as SchnorrSignature};

use self::{
    mast::{Mast, XOnly},
    primitive::{Addr, Script, Signature},
};

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
        /// Error format of scripts
        ScriptFormatError,
        /// Error from mast generate address
        MastGenAddrError,
        /// Address not exist
        AddrNotExist,
        /// Error from mast generate Merkle proof
        MastGenMerProof,
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
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::apply_verify_threshold_signature(addr, signature, script)?;
            Self::deposit_event(Event::VerifySignature);
            Ok(())
        }
    }
}

impl<T: Config> Pallet<T> {
    fn apply_generate_address(scripts: Vec<Script>) -> Result<Addr, DispatchError> {
        if let Ok(s) = XOnly::from_vec(scripts.clone()) {
            let mast = Mast::new(Vec::from(&s[1..]));
            if let Ok(addr) = mast.generate_address(&s[0]) {
                AddrToScript::<T>::insert(Vec::from(addr.clone()), scripts);
                Ok(Vec::from(addr))
            } else {
                Err(Error::<T>::MastGenAddrError.into())
            }
        } else {
            Err(Error::<T>::ScriptFormatError.into())
        }
    }

    fn apply_verify_threshold_signature(
        addr: Addr,
        signature: Signature,
        script: Script,
    ) -> Result<bool, DispatchError> {
        if !AddrToScript::<T>::contains_key(addr.clone()) {
            return Err(Error::<T>::AddrNotExist.into());
        }

        let scripts = AddrToScript::<T>::get(addr);
        if let Ok(s) = XOnly::from_vec(scripts) {
            let mast = Mast::new(Vec::from(&s[1..]));

            if let Ok(s1) = XOnly::parse_slice(&script) {
                if let Ok(proof) = mast.generate_merkle_proof(&s1) {
                    // TODO: Remove unwrap

                    // to verify proof
                    //
                    // if the proof contains an executing script, the merkel root is calculated from here
                    let mut exec_script = proof[0];
                    // compute merkel root
                    for i in 1..proof.len() {
                        exec_script = tagged_branch(exec_script, proof[i]).unwrap();
                    }
                    let tweak = XOnly::parse_slice(&exec_script[..]).unwrap();
                    let tweaked = s[0].add_scalar(&tweak).unwrap();
                    // ensure that the final computed public key is the same as
                    // the public key of the address in the output
                    let pubkey = XOnly::parse_slice(&addr.as_slice()).unwrap();
                    if pubkey == tweaked {
                        return Err(Error::<T>::MastGenMerProof.into());
                    }
                    // to verify signature
                    let sig = SchnorrSignature::from_bytes(&signature.as_slice()).unwrap();

                    // TODO: Use the correct public key for signature verification
                    // Which is the public key used to verify the signature and can there be some clarification?
                    let agg_pubkey = PublicKey::from_bytes(&script).unwrap();
                    let ctx = signing_context(b"substrate");
                    // ctx.bytes(msg), which is this msg?
                    if !agg_pubkey.verify(ctx.bytes(&script), &sig).is_ok() {
                        return Err(Error::<T>::MastGenMerProof.into());
                    }
                    Ok(true)
                } else {
                    Err(Error::<T>::MastGenMerProof.into())
                }
            } else {
                Err(Error::<T>::ScriptFormatError.into())
            }
        } else {
            Err(Error::<T>::ScriptFormatError.into())
        }
    }
}

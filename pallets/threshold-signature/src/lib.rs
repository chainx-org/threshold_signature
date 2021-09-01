#![cfg_attr(not(feature = "std"), no_std)]

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
        _signature: Signature,
        script: Script,
    ) -> Result<bool, DispatchError> {
        if !AddrToScript::<T>::contains_key(addr.clone()) {
            return Err(Error::<T>::AddrNotExist.into());
        }

        let scripts = AddrToScript::<T>::get(addr);
        if let Ok(s) = XOnly::from_vec(scripts) {
            let mast = Mast::new(Vec::from(&s[1..]));

            if let Ok(s1) = XOnly::parse_slice(&script) {
                if let Ok(_proof) = mast.generate_merkle_proof(&s1) {
                    // todo! verify proof
                    // todo! verify signature
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

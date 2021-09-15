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
    mast::{tweak_pubkey, Mast, XOnly},
    primitive::{Message, Script, Signature},
};
use crate::primitive::{OpCode, ScriptHash};
use codec::{Decode, Encode};
use frame_support::{dispatch::DispatchResult, sp_runtime::traits::StaticLookup, traits::Currency};
use frame_support::{
    dispatch::{DispatchError, DispatchResultWithPostInfo, PostDispatchInfo},
    inherent::Vec,
};
use frame_system::RawOrigin;
use hashes::{sha256, Hash};
use mast::{tagged_branch, ScriptMerkleNode};
pub use pallet::*;
use schnorrkel::{signing_context, PublicKey, Signature as SchnorrSignature};
use sp_core::sp_std::convert::TryFrom;
use sp_std::prelude::*;

type BalanceOf<T> =
    <pallet_balances::Pallet<T> as Currency<<T as frame_system::Config>::AccountId>>::Balance;

#[frame_support::pallet]
pub mod pallet {
    use super::*;
    use crate::primitive::{OpCode, ScriptHash};
    use frame_support::{
        dispatch::{Dispatchable, GetDispatchInfo},
        pallet_prelude::*,
    };
    use frame_system::pallet_prelude::*;

    /// Configure the pallet by specifying the parameters and types on which it depends.
    #[pallet::config]
    pub trait Config: frame_system::Config + pallet_balances::Config {
        /// Because this pallet emits events, it depends on the runtime's definition of an event.
        type Event: From<Event<Self>> + IsType<<Self as frame_system::Config>::Event>;
        /// A dispatchable call.
        type Call: Parameter
            + Dispatchable<Origin = Self::Origin, PostInfo = PostDispatchInfo>
            + GetDispatchInfo
            + From<frame_system::Call<Self>>;
        /// Weight information for extrinsics in this pallet.
        type WeightInfo: WeightInfo;
    }

    #[pallet::pallet]
    #[pallet::generate_store(pub (super) trait Store)]
    pub struct Pallet<T>(_);

    #[pallet::storage]
    #[pallet::getter(fn addr_to_script)]
    pub type AddrToScript<T: Config> =
        StorageMap<_, Twox64Concat, T::AccountId, Vec<Script>, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn script_hash_to_addr)]
    pub type ScriptHashToAddr<T: Config> =
        StorageMap<_, Twox64Concat, ScriptHash, T::AccountId, ValueQuery>;

    #[pallet::event]
    #[pallet::metadata(T::AccountId = "AccountId")]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Submit scripts to generate address. [addr]
        GenerateAddress(T::AccountId),
        /// Verify threshold signature and upload script hash. [script hash, addr]
        PassScript(Vec<u8>, T::AccountId),
        /// Execute script. [account, addr, opcode, amount, time lock]
        ExecuteScript(
            T::AccountId,
            T::AccountId,
            OpCode,
            BalanceOf<T>,
            (T::BlockNumber, T::BlockNumber),
        ),
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
        /// Mismatch time lock
        MisMatchTimeLock,
        /// Scripts that did not pass verification
        NoPassScript,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Generate threshold signature address according to the script provided by the user.
        ///
        /// - `scripts`: The first parameter is inner pubkey. The remaining parameters are other
        /// scripts. For example, inner pubkey can be the aggregate public
        /// key of ABC, and other scripts can be the aggregate public key of AB, BC and AC.
        #[pallet::weight(< T as Config >::WeightInfo::generate_address())]
        pub fn generate_address(origin: OriginFor<T>, scripts: Vec<Vec<u8>>) -> DispatchResult {
            ensure_signed(origin)?;
            let addr = Self::apply_generate_address(scripts)?;
            Self::deposit_event(Event::GenerateAddress(addr));
            Ok(())
        }
        // TODO fix annotation
        /// Verify the multi-signature address and then call other transactions.
        ///
        /// - `addr`: Represents a multi-signature address. For example, the aggregate public key
        /// of ABC
        /// - `signature`: Usually represents the aggregate signature of m individuals. For example,
        /// the aggregate signature of AB
        /// - `script`: Usually represents the aggregate public key of m individuals. For example,
        /// the aggregate public key of AB
        /// - `message`: Message used in the signing process.
        /// - `call`: The call to be executed.
        #[pallet::weight(< T as Config >::WeightInfo::pass_script())]
        pub fn pass_script(
            origin: OriginFor<T>,
            addr: T::AccountId,
            signature: Vec<u8>,
            script: Vec<u8>,
            message: Vec<u8>,
            script_hash: ScriptHash,
        ) -> DispatchResult {
            ensure_signed(origin)?;
            Self::apply_pass_script(addr, signature, script, message, script_hash)
        }

        // TODO add annotation and weight
        #[pallet::weight(< T as Config >::WeightInfo::exec_script())]
        pub fn exec_script(
            origin: OriginFor<T>,
            call: OpCode,
            amount: BalanceOf<T>,
            time_lock: (T::BlockNumber, T::BlockNumber),
        ) -> DispatchResultWithPostInfo {
            let who = ensure_signed(origin)?;
            let script_hash =
                Self::compute_script_hash(who.clone(), call.clone(), amount, time_lock);
            Self::apply_exec_script(who, call, amount, time_lock, script_hash)?;
            Ok(Some(<T as Config>::WeightInfo::exec_script()).into())
        }
    }
}

impl<T: Config> Pallet<T> {
    fn apply_generate_address(scripts: Vec<Script>) -> Result<T::AccountId, DispatchError> {
        let script_nodes = scripts
            .iter()
            .map(|script| XOnly::try_from(script.clone()))
            .collect::<Result<Vec<XOnly>, _>>()
            .map_err::<Error<T>, _>(Into::into)?;

        let mast = Mast::new(Vec::from(&script_nodes[1..]));
        let addr = mast
            .generate_tweak_pubkey(&script_nodes[0])
            .map_err::<Error<T>, _>(Into::into)?;

        let account = T::AccountId::decode(&mut &addr[..]).unwrap_or_default();
        AddrToScript::<T>::insert(account.clone(), scripts);
        Ok(account)
    }

    pub fn apply_pass_script(
        addr: T::AccountId,
        signature: Signature,
        full_script: Script,
        message: Message,
        script_hash: ScriptHash,
    ) -> DispatchResult {
        let executable =
            Self::apply_verify_threshold_signature(addr.clone(), signature, full_script, message)?;

        if executable {
            // TODO What if the same script corresponds to different threshold signature addresses？
            ScriptHashToAddr::<T>::insert(script_hash.clone(), addr.clone());
            Self::deposit_event(Event::<T>::PassScript(script_hash, addr));
        }
        Ok(())
    }

    pub fn apply_verify_threshold_signature(
        addr: T::AccountId,
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
        addr: T::AccountId,
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
        let output_address = T::AccountId::decode(&mut &tweaked[..]).unwrap_or_default();

        // ensure that the final computed public key is the same as
        // the public key of the address in the output
        if addr != output_address {
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

    pub fn compute_script_hash(
        account: T::AccountId,
        call: OpCode,
        amount: BalanceOf<T>,
        time_lock: (T::BlockNumber, T::BlockNumber),
    ) -> ScriptHash {
        let mut input: Vec<u8> = vec![];
        input.extend(&account.encode());
        input.push(call.into());
        input.extend(&amount.encode());
        input.extend(&time_lock.0.encode());
        input.extend(&time_lock.1.encode());
        sha256::Hash::hash(&input).to_vec()
    }

    fn apply_exec_script(
        account: T::AccountId,
        call: OpCode,
        amount: BalanceOf<T>,
        time_lock: (T::BlockNumber, T::BlockNumber),
        script_hash: ScriptHash,
    ) -> DispatchResultWithPostInfo {
        if !ScriptHashToAddr::<T>::contains_key(script_hash.clone()) {
            return Err(Error::<T>::NoPassScript.into());
        }
        let addr = Self::script_hash_to_addr(script_hash.clone());
        let current_block = frame_system::Pallet::<T>::block_number();
        if time_lock.0 <= current_block && current_block <= time_lock.1 {
            match call {
                OpCode::Transfer => {
                    let _ = pallet_balances::Pallet::<T>::transfer(
                        RawOrigin::Signed(addr.clone()).into(),
                        T::Lookup::unlookup(account.clone()),
                        amount.into(),
                    )?;
                    ScriptHashToAddr::<T>::remove(script_hash);
                    Self::deposit_event(Event::<T>::ExecuteScript(
                        account, addr, call, amount, time_lock,
                    ));
                }
            }
            Ok(Some(<T as Config>::WeightInfo::exec_script()).into())
        } else {
            Ok(Some(<T as Config>::WeightInfo::exec_script()).into())
            // TODO should return error
            // Err(Error::<T>::MisMatchTimeLock.into())
        }
    }
}

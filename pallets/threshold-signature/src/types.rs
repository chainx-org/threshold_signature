use schnorrkel::SignatureError;

use crate::mast::error::MastError;
use crate::mast::key::Error as KeyError;
use crate::{Config, Error};

impl<T: Config> From<MastError> for Error<T> {
    fn from(err: MastError) -> Self {
        match err {
            MastError::NoScripts => Error::<T>::BadMast,
            MastError::BadFormat(_) => Error::<T>::BadMast,
            MastError::FromHexError(_) => Error::<T>::BadMast,
            MastError::MastBuildError => Error::<T>::MastGenMerProofError,
            MastError::EncodeToBech32Error(_) => Error::<T>::MastGenAddrError,
        }
    }
}

impl<T: Config> From<KeyError> for Error<T> {
    fn from(_: KeyError) -> Self {
        Error::<T>::BadMast
    }
}

impl<T: Config> From<SignatureError> for Error<T> {
    fn from(_: SignatureError) -> Self {
        Error::<T>::InvalidSignature
    }
}

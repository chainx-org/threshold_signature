use schnorrkel::SignatureError;

use crate::mast::error::MastError;
use crate::{Config, Error};

impl<T: Config> From<MastError> for Error<T> {
    fn from(err: MastError) -> Self {
        match err {
            MastError::NoScripts => Error::<T>::BadMast,
            MastError::BadFormat(_) => Error::<T>::BadMast,
            MastError::FromHexError(_) => Error::<T>::BadMast,
            MastError::MastBuildError => Error::<T>::MastGenMerProofError,
            MastError::EncodeToBech32Error(_) => Error::<T>::MastGenAddrError,
            MastError::XOnlyInvalidLength => Error::<T>::XOnlyInvalidLength
        }
    }
}

impl<T: Config> From<SignatureError> for Error<T> {
    fn from(_: SignatureError) -> Self {
        Error::<T>::InvalidSignature
    }
}

use schnorrkel::SignatureError;

use crate::mast::error::MastError;
use crate::{Config, Error};

impl<T: Config> From<MastError> for Error<T> {
    fn from(err: MastError) -> Self {
        match err {
            MastError::InvalidConstructedMast(_s) => Error::<T>::BadMast,
            MastError::FromHexError(_) => Error::<T>::BadMast,
            MastError::MastBuildError => Error::<T>::MastGenMerProofError,
            MastError::EncodeToBech32Error(_) => Error::<T>::MastGenAddrError,
            MastError::IoError(_) => Error::<T>::BadMast,
            MastError::KeyPairError(_) => Error::<T>::BadMast,
        }
    }
}

impl<T: Config> From<SignatureError> for Error<T> {
    fn from(_: SignatureError) -> Self {
        Error::<T>::InvalidSignature
    }
}

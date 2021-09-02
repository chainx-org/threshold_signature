use super::*;
use core::result;
use hex::FromHexError;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MastError {
    /// When header merkle root don't match to the root calculated from the partial merkle tree
    // MerkleRootMismatch,
    /// When partial merkle tree contains no scripts
    NoScripts,
    /// When there are too many scripts
    // TooManyScripts,

    /// General format error
    BadFormat(String),

    FromHexError(String),
    // SerializeLengthError,
    /// Indicates whether the MAST build error
    MastBuildError,
    /// Bech32m encoding error
    EncodeToBech32Error(String),
    /// XOnly Invalid length
    XOnlyInvalidLength
}

impl From<io::Error> for MastError {
    fn from(_: io::Error) -> Self {
        unreachable!()
    }
}

impl From<bech32::Error> for MastError {
    fn from(e: bech32::Error) -> Self {
        match e {
            bech32::Error::MissingSeparator => {
                MastError::EncodeToBech32Error("MissingSeparator".to_string())
            }
            bech32::Error::InvalidChecksum => {
                MastError::EncodeToBech32Error("InvalidChecksum".to_string())
            }
            bech32::Error::InvalidLength => {
                MastError::EncodeToBech32Error("InvalidLength".to_string())
            }
            bech32::Error::InvalidChar(c) => {
                MastError::EncodeToBech32Error(format!("InvalidChar {}", c))
            }
            bech32::Error::InvalidData(d) => {
                MastError::EncodeToBech32Error(format!("InvalidData {}", d))
            }
            bech32::Error::InvalidPadding => {
                MastError::EncodeToBech32Error("InvalidPadding".to_string())
            }
            bech32::Error::MixedCase => MastError::EncodeToBech32Error("MixedCase".to_string()),
        }
    }
}

impl From<FromHexError> for MastError {
    fn from(e: FromHexError) -> Self {
        match e {
            FromHexError::InvalidHexCharacter { c, index } => {
                MastError::FromHexError(format!("InvalidHexCharacter {}, {}", c, index))
            }
            FromHexError::OddLength => MastError::FromHexError("OddLength".to_string()),
            FromHexError::InvalidStringLength => {
                MastError::FromHexError("InvalidStringLength".to_string())
            }
        }
    }
}

impl From<hashes::hex::Error> for MastError {
    fn from(e: hashes::hex::Error) -> Self {
        match e {
            hashes::hex::Error::InvalidChar(c) => {
                MastError::FromHexError(format!("InvalidChar {}", c))
            }
            hashes::hex::Error::OddLengthString(c) => {
                MastError::FromHexError(format!("OddLengthString {}", c))
            }
            hashes::hex::Error::InvalidLength(a, b) => {
                MastError::FromHexError(format!("InvalidLength {},{}", a, b))
            }
        }
    }
}

pub type Result<T> = result::Result<T, MastError>;

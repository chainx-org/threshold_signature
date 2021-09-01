pub mod encode;
pub mod pmt;
// pub mod merkle_root;
mod error;
pub mod hash_types;
pub mod key;
pub mod mast;
pub mod taggedhash;

pub use encode::*;
pub use hash_types::*;
pub use mast::*;

#[cfg(feature = "std")]
use std::{
    fmt,
    io::{self, Cursor},
};

#[cfg(not(feature = "std"))]
use core2::io::{self, Cursor};

use self::key::PrivateKey;
#[cfg(not(feature = "std"))]
use alloc::{
    borrow::ToOwned,
    fmt, format,
    prelude::v1::Box,
    string::{String, ToString},
    vec,
    vec::Vec,
};

pub type XOnly = PrivateKey;

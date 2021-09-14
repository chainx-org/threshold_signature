// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.
#![cfg_attr(not(feature = "std"), no_std)]
use codec::{Decode, Encode};

use frame_support::inherent::Vec;
// TODO change into a suitable name
/// Script used to represent the public key
pub type Script = Vec<u8>;

/// Signature
pub type Signature = Vec<u8>;

/// Message used to indicate a signed message
pub type Message = Vec<u8>;

/// The hash of the custom script
pub type ScriptHash = Vec<u8>;

/// Opcodes in custom scripts
#[derive(Clone, Debug, Decode, Encode, PartialEq)]
pub enum OpCode{
    Transfer
}

impl From<OpCode> for u8{
    fn from(opcode: OpCode) -> Self {
        match opcode{
            OpCode::Transfer => 0u8
        }
    }
}

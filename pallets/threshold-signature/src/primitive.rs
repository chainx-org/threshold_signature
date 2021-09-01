// Copyright 2019-2020 ChainX Project Authors. Licensed under GPL-3.0.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::inherent::Vec;

/// bech32m address
pub type Addr = Vec<u8>;

/// Script
pub type Script = Vec<u8>;

/// Signature
pub type Signature = Vec<u8>;

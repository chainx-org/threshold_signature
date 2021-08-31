#![allow(dead_code)]
use std::{
    error, fmt,
    io::{self, Cursor},
};

use super::*;
use hashes::{Hash, hex::ToHex, sha256d};

#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec, string::String, collections::linked_list::Cursor, prelude::v1::Box};

/// Encoding error
#[derive(Debug)]
pub enum Error {
    /// And I/O error
    Io(io::Error),
    /// Tried to allocate an oversized vector
    OversizedVectorAllocation {
        /// The capacity requested
        requested: usize,
        /// The maximum capacity
        max: usize,
    },
    /// Checksum was invalid
    InvalidChecksum {
        /// The expected checksum
        expected: [u8; 4],
        /// The invalid checksum
        actual: [u8; 4],
    },
    /// VarInt was encoded in a non-minimal way
    NonMinimalVarInt,
    /// Parsing error
    ParseFailed(&'static str),
    /// Unsupported Segwit flag
    UnsupportedSegwitFlag(u8),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Io(ref e) => write!(f, "I/O error: {}", e),
            Error::OversizedVectorAllocation {
                requested: ref r,
                max: ref m,
            } => write!(
                f,
                "allocation of oversized vector: requested {}, maximum {}",
                r, m
            ),
            Error::InvalidChecksum {
                expected: ref e,
                actual: ref a,
            } => write!(
                f,
                "invalid checksum: expected {}, actual {}",
                e.to_hex(),
                a.to_hex()
            ),
            Error::NonMinimalVarInt => write!(f, "non-minimal varint"),
            Error::ParseFailed(ref e) => write!(f, "parse failed: {}", e),
            Error::UnsupportedSegwitFlag(ref swflag) => {
                write!(f, "unsupported segwit version: {}", swflag)
            }
        }
    }
}

#[cfg(feature = "std")]
impl ::std::error::Error for Error {
    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Io(ref e) => Some(e),
            Error::OversizedVectorAllocation { .. }
            | Error::InvalidChecksum { .. }
            | Error::NonMinimalVarInt
            | Error::ParseFailed(..)
            | Error::UnsupportedSegwitFlag(..) => None,
        }
    }
}

#[doc(hidden)]
impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

/// Encode an object into a vector
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data.consensus_encode(&mut encoder).unwrap();
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encode an object into a hex-encoded string
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    serialize(data)[..].to_hex()
}

/// Deserialize an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed(
            "data not consumed entirely when explicitly deserializing",
        ))
    }
}
/// Deserialize an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

macro_rules! define_slice_to_be {
    ($name: ident, $type: ty) => {
        #[inline]
        pub fn $name(slice: &[u8]) -> $type {
            assert_eq!(slice.len(), ::core::mem::size_of::<$type>());
            let mut res = 0;
            for i in 0..::core::mem::size_of::<$type>() {
                res |= (slice[i] as $type) << (::core::mem::size_of::<$type>() - i - 1) * 8;
            }
            res
        }
    };
}
macro_rules! define_slice_to_le {
    ($name: ident, $type: ty) => {
        #[inline]
        pub fn $name(slice: &[u8]) -> $type {
            assert_eq!(slice.len(), ::core::mem::size_of::<$type>());
            let mut res = 0;
            for i in 0..::core::mem::size_of::<$type>() {
                res |= (slice[i] as $type) << i * 8;
            }
            res
        }
    };
}
macro_rules! define_be_to_array {
    ($name: ident, $type: ty, $byte_len: expr) => {
        #[inline]
        pub fn $name(val: $type) -> [u8; $byte_len] {
            debug_assert_eq!(::core::mem::size_of::<$type>(), $byte_len); // size_of isn't a constfn in 1.22
            let mut res = [0; $byte_len];
            for i in 0..$byte_len {
                res[i] = ((val >> ($byte_len - i - 1) * 8) & 0xff) as u8;
            }
            res
        }
    };
}
macro_rules! define_le_to_array {
    ($name: ident, $type: ty, $byte_len: expr) => {
        #[inline]
        pub fn $name(val: $type) -> [u8; $byte_len] {
            debug_assert_eq!(::core::mem::size_of::<$type>(), $byte_len); // size_of isn't a constfn in 1.22
            let mut res = [0; $byte_len];
            for i in 0..$byte_len {
                res[i] = ((val >> i * 8) & 0xff) as u8;
            }
            res
        }
    };
}

define_slice_to_be!(slice_to_u32_be, u32);
define_slice_to_be!(slice_to_u64_be, u64);
define_be_to_array!(u32_to_array_be, u32, 4);
define_be_to_array!(u64_to_array_be, u64, 8);
define_slice_to_le!(slice_to_u16_le, u16);
define_slice_to_le!(slice_to_u32_le, u32);
define_slice_to_le!(slice_to_u64_le, u64);
define_le_to_array!(u16_to_array_le, u16, 2);
define_le_to_array!(u32_to_array_le, u32, 4);
define_le_to_array!(u64_to_array_le, u64, 8);

#[inline]
pub fn i16_to_array_le(val: i16) -> [u8; 2] {
    u16_to_array_le(val as u16)
}
#[inline]
pub fn slice_to_i16_le(slice: &[u8]) -> i16 {
    slice_to_u16_le(slice) as i16
}
#[inline]
pub fn slice_to_i32_le(slice: &[u8]) -> i32 {
    slice_to_u32_le(slice) as i32
}
#[inline]
pub fn i32_to_array_le(val: i32) -> [u8; 4] {
    u32_to_array_le(val as u32)
}
#[inline]
pub fn slice_to_i64_le(slice: &[u8]) -> i64 {
    slice_to_u64_le(slice) as i64
}
#[inline]
pub fn i64_to_array_le(val: i64) -> [u8; 8] {
    u64_to_array_le(val as u64)
}

macro_rules! define_chunk_slice_to_int {
    ($name: ident, $type: ty, $converter: ident) => {
        #[inline]
        pub fn $name(inp: &[u8], outp: &mut [$type]) {
            assert_eq!(inp.len(), outp.len() * ::core::mem::size_of::<$type>());
            for (outp_val, data_bytes) in outp
                .iter_mut()
                .zip(inp.chunks(::core::mem::size_of::<$type>()))
            {
                *outp_val = $converter(data_bytes);
            }
        }
    };
}
define_chunk_slice_to_int!(bytes_to_u64_slice_le, u64, slice_to_u64_le);

/// Extensions of `Write` to encode data as per Bitcoin consensus
pub trait WriteExt {
    /// Output a 64-bit uint
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Output a 32-bit uint
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Output a 16-bit uint
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Output a 8-bit uint
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Output a 64-bit int
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Output a 32-bit int
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Output a 16-bit int
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Output a 8-bit int
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Output a boolean
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Output a byte slice
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error>;
}

/// Extensions of `Read` to decode data as per Bitcoin consensus
pub trait ReadExt {
    /// Read a 64-bit uint
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Read a 32-bit uint
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Read a 16-bit uint
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Read a 8-bit uint
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Read a 64-bit int
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Read a 32-bit int
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Read a 16-bit int
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Read a 8-bit int
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Read a boolean
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Read a byte slice
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty, $writefn:ident) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> Result<(), io::Error> {
            self.write_all(&$writefn(v))
        }
    };
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $readfn:ident, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> Result<$val_type, Error> {
            debug_assert_eq!(::core::mem::size_of::<$val_type>(), $byte_len); // size_of isn't a constfn in 1.22
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(Error::Io)?;
            Ok($readfn(&val))
        }
    };
}

impl<W: io::Write> WriteExt for W {
    encoder_fn!(emit_u64, u64, u64_to_array_le);
    encoder_fn!(emit_u32, u32, u32_to_array_le);
    encoder_fn!(emit_u16, u16, u16_to_array_le);
    encoder_fn!(emit_i64, i64, i64_to_array_le);
    encoder_fn!(emit_i32, i32, i32_to_array_le);
    encoder_fn!(emit_i16, i16, i16_to_array_le);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> {
        self.write_all(&[v])
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error> {
        self.write_all(v)
    }
}

impl<R: io::Read> ReadExt for R {
    decoder_fn!(read_u64, u64, slice_to_u64_le, 8);
    decoder_fn!(read_u32, u32, slice_to_u32_le, 4);
    decoder_fn!(read_u16, u16, slice_to_u16_le, 2);
    decoder_fn!(read_i64, i64, slice_to_i64_le, 8);
    decoder_fn!(read_i32, i32, slice_to_i32_le, 4);
    decoder_fn!(read_i16, i16, slice_to_i16_le, 2);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0])
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0] as i8)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        ReadExt::read_i8(self).map(|bit| bit != 0)
    }
    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error> {
        self.read_exact(slice).map_err(Error::Io)
    }
}

/// Maximum size, in bytes, of a vector we are allowed to decode
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Data which can be encoded in a consensus-consistent way
pub trait Encodable {
    /// Encode an object with a well-defined format.
    /// Returns the number of bytes written on success.
    ///
    /// The only errors returned are errors propagated from the writer.
    fn consensus_encode<W: io::Write>(&self, writer: W) -> Result<usize, io::Error>;
}

/// Data which can be encoded in a consensus-consistent way
pub trait Decodable: Sized {
    /// Decode an object with a well-defined format
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error>;
}

/// A variable-length unsigned integer
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64);

/// Data which must be preceded by a 4-byte checksum
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData(pub Vec<u8>);

// Primitive types
macro_rules! impl_int_encodable {
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => {
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                ReadExt::$meth_dec(&mut d)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<S: WriteExt>(&self, mut s: S) -> Result<usize, io::Error> {
                s.$meth_enc(*self)?;
                Ok(core::mem::size_of::<$ty>())
            }
        }
    };
}

impl_int_encodable!(u8, read_u8, emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8, read_i8, emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

impl VarInt {
    /// Gets the length of this VarInt when encoded.
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1),
    /// and 9 otherwise.
    #[inline]
    pub fn len(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }
}

impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(s)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                s.emit_u8(0xFD)?;
                (self.0 as u16).consensus_encode(s)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                s.emit_u8(0xFE)?;
                (self.0 as u32).consensus_encode(s)?;
                Ok(5)
            }
            _ => {
                s.emit_u8(0xFF)?;
                (self.0 as u64).consensus_encode(s)?;
                Ok(9)
            }
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let n = ReadExt::read_u8(&mut d)?;
        match n {
            0xFF => {
                let x = ReadExt::read_u64(&mut d)?;
                if x < 0x100000000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x))
                }
            }
            0xFE => {
                let x = ReadExt::read_u32(&mut d)?;
                if x < 0x10000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            0xFD => {
                let x = ReadExt::read_u16(&mut d)?;
                if x < 0xFD {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt(x as u64))
                }
            }
            n => Ok(VarInt(n as u64)),
        }
    }
}

// Booleans
impl Encodable for bool {
    #[inline]
    fn consensus_encode<S: WriteExt>(&self, mut s: S) -> Result<usize, io::Error> {
        s.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<bool, Error> {
        ReadExt::read_bool(&mut d)
    }
}

// Strings
impl Encodable for String {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(&mut s)?;
        s.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(d)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}

// Arrays
macro_rules! impl_array {
    ( $size:expr ) => {
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<S: WriteExt>(&self, mut s: S) -> Result<usize, io::Error> {
                s.emit_slice(&self[..])?;
                Ok(self.len())
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let mut ret = [0; $size];
                d.read_slice(&mut ret)?;
                Ok(ret)
            }
        }
    };
}

impl_array!(2);
impl_array!(4);
impl_array!(8);
impl_array!(10);
impl_array!(12);
impl_array!(16);
impl_array!(32);
impl_array!(33);

impl Decodable for [u16; 8] {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut res = [0; 8];
        for item in &mut res {
            *item = Decodable::consensus_decode(&mut d)?;
        }
        Ok(res)
    }
}

impl Encodable for [u16; 8] {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        for c in self.iter() {
            c.consensus_encode(&mut s)?;
        }
        Ok(16)
    }
}

// Vectors
macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
                let mut len = 0;
                len += VarInt(self.len() as u64).consensus_encode(&mut s)?;
                for c in self.iter() {
                    len += c.consensus_encode(&mut s)?;
                }
                Ok(len)
            }
        }
        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                let len = VarInt::consensus_decode(&mut d)?.0;
                let byte_size = (len as usize)
                    .checked_mul(core::mem::size_of::<$type>())
                    .ok_or(self::Error::ParseFailed("Invalid length"))?;
                if byte_size > MAX_VEC_SIZE {
                    return Err(self::Error::OversizedVectorAllocation {
                        requested: byte_size,
                        max: MAX_VEC_SIZE,
                    });
                }
                let mut ret = Vec::with_capacity(len as usize);
                let mut d = d.take(MAX_VEC_SIZE as u64);
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode(&mut d)?);
                }
                Ok(ret)
            }
        }
    };
}
// impl_vec!(BlockHash);
// impl_vec!(FilterHash);
// impl_vec!(FilterHeader);
impl_vec!(ScriptMerkleNode);
// impl_vec!(Transaction);
// impl_vec!(TxOut);
// impl_vec!(TxIn);
impl_vec!(Vec<u8>);
impl_vec!(u32);
impl_vec!(u64);

// #[cfg(feature = "std")] impl_vec!(Inventory);
// #[cfg(feature = "std")] impl_vec!((u32, Address));
// #[cfg(feature = "std")] impl_vec!(AddrV2Message);

fn consensus_encode_with_size<S: io::Write>(data: &[u8], mut s: S) -> Result<usize, io::Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(&mut s)?;
    s.emit_slice(data)?;
    Ok(vi_len + data.len())
}

impl Encodable for Vec<u8> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, s)
    }
}

impl Decodable for Vec<u8> {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(&mut d)?.0 as usize;
        if len > MAX_VEC_SIZE {
            return Err(self::Error::OversizedVectorAllocation {
                requested: len,
                max: MAX_VEC_SIZE,
            });
        }
        let mut ret = vec![0u8; len];
        d.read_slice(&mut ret)?;
        Ok(ret)
    }
}

impl Encodable for Box<[u8]> {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, s)
    }
}

impl Decodable for Box<[u8]> {
    #[inline]
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        <Vec<u8>>::consensus_decode(d).map(From::from)
    }
}

/// Do a double-SHA256 on some data and return the first 4 bytes
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

// Checked data
impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        (self.0.len() as u32).consensus_encode(&mut s)?;
        sha2_checksum(&self.0).consensus_encode(&mut s)?;
        s.emit_slice(&self.0)?;
        Ok(8 + self.0.len())
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = u32::consensus_decode(&mut d)?;
        if len > MAX_VEC_SIZE as u32 {
            return Err(self::Error::OversizedVectorAllocation {
                requested: len as usize,
                max: MAX_VEC_SIZE,
            });
        }
        let checksum = <[u8; 4]>::consensus_decode(&mut d)?;
        let mut ret = vec![0u8; len as usize];
        d.read_slice(&mut ret)?;
        let expected_checksum = sha2_checksum(&ret);
        if expected_checksum != checksum {
            Err(self::Error::InvalidChecksum {
                expected: expected_checksum,
                actual: checksum,
            })
        } else {
            Ok(CheckedData(ret))
        }
    }
}

// References
impl<'a, T: Encodable> Encodable for &'a T {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        (&**self).consensus_encode(s)
    }
}

// Tuples
macro_rules! tuple_encode {
    ($($x:ident),*) => (
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode<S: io::Write>(
                &self,
                mut s: S,
            ) -> Result<usize, io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(&mut s)?;)*
                Ok(len)
            }
        }

        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
                Ok(($({let $x = Decodable::consensus_decode(&mut d)?; $x }),*))
            }
        }
    );
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

impl Encodable for sha256d::Hash {
    fn consensus_encode<S: io::Write>(&self, s: S) -> Result<usize, io::Error> {
        self.into_inner().consensus_encode(s)
    }
}

impl Decodable for sha256d::Hash {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_inner(<<Self as Hash>::Inner>::consensus_decode(
            d,
        )?))
    }
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use super::{deserialize, serialize, CheckedData, Error, VarInt};
    use core::{
        fmt,
        mem::{self, discriminant},
    };
    #[test]
    fn serialize_int_test() {
        // bool
        assert_eq!(serialize(&false), vec![0u8]);
        assert_eq!(serialize(&true), vec![1u8]);
        // u8
        assert_eq!(serialize(&1u8), vec![1u8]);
        assert_eq!(serialize(&0u8), vec![0u8]);
        assert_eq!(serialize(&255u8), vec![255u8]);
        // u16
        assert_eq!(serialize(&1u16), vec![1u8, 0]);
        assert_eq!(serialize(&256u16), vec![0u8, 1]);
        assert_eq!(serialize(&5000u16), vec![136u8, 19]);
        // u32
        assert_eq!(serialize(&1u32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256u32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000u32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000u32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090u32), vec![10u8, 10, 10, 10]);
        // i32
        assert_eq!(serialize(&-1i32), vec![255u8, 255, 255, 255]);
        assert_eq!(serialize(&-256i32), vec![0u8, 255, 255, 255]);
        assert_eq!(serialize(&-5000i32), vec![120u8, 236, 255, 255]);
        assert_eq!(serialize(&-500000i32), vec![224u8, 94, 248, 255]);
        assert_eq!(serialize(&-168430090i32), vec![246u8, 245, 245, 245]);
        assert_eq!(serialize(&1i32), vec![1u8, 0, 0, 0]);
        assert_eq!(serialize(&256i32), vec![0u8, 1, 0, 0]);
        assert_eq!(serialize(&5000i32), vec![136u8, 19, 0, 0]);
        assert_eq!(serialize(&500000i32), vec![32u8, 161, 7, 0]);
        assert_eq!(serialize(&168430090i32), vec![10u8, 10, 10, 10]);
        // u64
        assert_eq!(serialize(&1u64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256u64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000u64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000u64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(
            serialize(&723401728380766730u64),
            vec![10u8, 10, 10, 10, 10, 10, 10, 10]
        );
        // i64
        assert_eq!(
            serialize(&-1i64),
            vec![255u8, 255, 255, 255, 255, 255, 255, 255]
        );
        assert_eq!(
            serialize(&-256i64),
            vec![0u8, 255, 255, 255, 255, 255, 255, 255]
        );
        assert_eq!(
            serialize(&-5000i64),
            vec![120u8, 236, 255, 255, 255, 255, 255, 255]
        );
        assert_eq!(
            serialize(&-500000i64),
            vec![224u8, 94, 248, 255, 255, 255, 255, 255]
        );
        assert_eq!(
            serialize(&-723401728380766730i64),
            vec![246u8, 245, 245, 245, 245, 245, 245, 245]
        );
        assert_eq!(serialize(&1i64), vec![1u8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&256i64), vec![0u8, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&5000i64), vec![136u8, 19, 0, 0, 0, 0, 0, 0]);
        assert_eq!(serialize(&500000i64), vec![32u8, 161, 7, 0, 0, 0, 0, 0]);
        assert_eq!(
            serialize(&723401728380766730i64),
            vec![10u8, 10, 10, 10, 10, 10, 10, 10]
        );
    }

    fn test_varint_len(varint: VarInt, expected: usize) {
        let mut encoder = vec![];
        assert_eq!(varint.consensus_encode(&mut encoder).unwrap(), expected);
        assert_eq!(varint.len(), expected);
    }

    #[test]
    fn serialize_checkeddata_test() {
        let cd = CheckedData(vec![1u8, 2, 3, 4, 5]);
        assert_eq!(
            serialize(&cd),
            vec![5, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]
        );
    }

    #[test]
    fn serialize_vector_test() {
        assert_eq!(serialize(&vec![1u8, 2, 3]), vec![3u8, 1, 2, 3]);
        // TODO: test vectors of more interesting objects
    }

    #[test]
    fn serialize_strbuf_test() {
        assert_eq!(
            serialize(&"Andrew".to_string()),
            vec![6u8, 0x41, 0x6e, 0x64, 0x72, 0x65, 0x77]
        );
    }

    #[test]
    fn deserialize_int_test() {
        // bool
        assert!((deserialize(&[58u8, 0]) as Result<bool, _>).is_err());
        assert_eq!(deserialize(&[58u8]).ok(), Some(true));
        assert_eq!(deserialize(&[1u8]).ok(), Some(true));
        assert_eq!(deserialize(&[0u8]).ok(), Some(false));
        assert!((deserialize(&[0u8, 1]) as Result<bool, _>).is_err());

        // u8
        assert_eq!(deserialize(&[58u8]).ok(), Some(58u8));

        // u16
        assert_eq!(deserialize(&[0x01u8, 0x02]).ok(), Some(0x0201u16));
        assert_eq!(deserialize(&[0xABu8, 0xCD]).ok(), Some(0xCDABu16));
        assert_eq!(deserialize(&[0xA0u8, 0x0D]).ok(), Some(0xDA0u16));
        let failure16: Result<u16, _> = deserialize(&[1u8]);
        assert!(failure16.is_err());

        // u32
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABu32));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD]).ok(),
            Some(0xCDAB0DA0u32)
        );
        let failure32: Result<u32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failure32.is_err());
        // TODO: test negative numbers
        assert_eq!(deserialize(&[0xABu8, 0xCD, 0, 0]).ok(), Some(0xCDABi32));
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0x2D]).ok(),
            Some(0x2DAB0DA0i32)
        );
        let failurei32: Result<i32, _> = deserialize(&[1u8, 2, 3]);
        assert!(failurei32.is_err());

        // u64
        assert_eq!(
            deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(),
            Some(0xCDABu64)
        );
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(0x99000099CDAB0DA0u64)
        );
        let failure64: Result<u64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failure64.is_err());
        // TODO: test negative numbers
        assert_eq!(
            deserialize(&[0xABu8, 0xCD, 0, 0, 0, 0, 0, 0]).ok(),
            Some(0xCDABi64)
        );
        assert_eq!(
            deserialize(&[0xA0u8, 0x0D, 0xAB, 0xCD, 0x99, 0, 0, 0x99]).ok(),
            Some(-0x66ffff663254f260i64)
        );
        let failurei64: Result<i64, _> = deserialize(&[1u8, 2, 3, 4, 5, 6, 7]);
        assert!(failurei64.is_err());
    }

    fn test_len_is_max_vec<T>()
    where
        Vec<T>: Decodable,
        T: fmt::Debug,
    {
        let rand_io_err = Error::Io(io::Error::new(io::ErrorKind::Other, ""));
        let varint = VarInt((super::MAX_VEC_SIZE / mem::size_of::<T>()) as u64);
        let err = deserialize::<Vec<T>>(&serialize(&varint)).unwrap_err();
        assert_eq!(discriminant(&err), discriminant(&rand_io_err));
    }

    #[test]
    fn deserialize_checkeddata_test() {
        let cd: Result<CheckedData, _> =
            deserialize(&[5u8, 0, 0, 0, 162, 107, 175, 90, 1, 2, 3, 4, 5]);
        assert_eq!(cd.ok(), Some(CheckedData(vec![1u8, 2, 3, 4, 5])));
    }

    #[test]
    fn limit_read_test() {
        let witness = vec![vec![0u8; 3_999_999]; 2];
        let ser = serialize(&witness);
        let mut reader = io::Cursor::new(ser);
        let err = Vec::<Vec<u8>>::consensus_decode(&mut reader);
        assert!(err.is_err());
    }
}

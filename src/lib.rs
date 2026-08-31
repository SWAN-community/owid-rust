/* ****************************************************************************
 * Copyright 2026 51 Degrees Mobile Experts Limited (51degrees.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 * ***************************************************************************/

//! # Open Web Id (OWID)
//!
//! Simple cryptographically auditable identifiers and processors implemented
//! in Rust.
//!
//! Read the [OWID](https://github.com/SWAN-community/owid) project to learn
//! more about the concepts before looking into this implementation. This
//! crate creates, signs, serializes, and verifies OWIDs.
//!
//! ## Data structure
//!
//! An OWID is a compact binary structure. The fields appear in the following
//! order. Multi byte integers are little endian.
//!
//! | Field          | Bytes               | Description                                                  |
//! |----------------|---------------------|--------------------------------------------------------------|
//! | Version        | 1                   | The byte version of the OWID. Always the first byte.         |
//! | Domain         | length + 1          | Domain associated with the creator, null (0) terminated.     |
//! | Date           | 4 (2 for version 1) | Minutes elapsed since 2020-01-01 UTC as an unsigned integer. |
//! | Payload length | 4                   | Number of bytes that form the payload.                       |
//! | Payload        | variable            | Bytes that form the payload, if any.                         |
//! | Signature      | 64                  | ECDSA P-256 signature as the r and s values concatenated.    |
//!
//! Version 1 stored the date as a two byte big endian count of hours since
//! the base date. Versions 1 and 2 are deprecated and supported for reading
//! existing data only.
//!
//! The signature is the end of the OWID. Reading a buffer that holds one
//! OWID, the payload length must leave exactly the 64 signature bytes after
//! the payload, so a buffer with bytes after the signature, or with fewer
//! than 64 bytes after the payload, is refused as malformed. Reading one
//! from the front of a longer buffer with [`Owid::read_from_prefix`], the
//! payload and the 64 signature bytes must be present and whatever follows
//! them is handed back, because it may be the next frame. A payload
//! declared longer than the bytes supplied is data that stopped early
//! there, rather than a declaration disagreeing with bytes that are all
//! present.
//!
//! A frame may instead hold the one byte marker written by
//! [`Owid::empty_to_buffer`], which stands for a node that is not there. It
//! is not an OWID and carries no signature, so no OWID is handed back for
//! one, and both reads name it [`ParseStatus::AbsentNode`] so that a caller
//! walking a run of frames can tell an absent node from a malformed one.
//!
//! The domain is found by reading forward to its null terminator, and that
//! read stops at the maximum length a domain name is allowed to be, so a
//! buffer whose terminator is missing or corrupted is refused rather than
//! read to the end. The same maximum binds a creator, so a longer domain
//! is refused when it is supplied and again when an OWID carrying it is
//! serialized, which keeps this crate from writing something it would
//! refuse to read.
//!
//! ## Signing
//!
//! The signing algorithm generates a SHA-256 digest of the OWID data
//! structure without the signature field, optionally followed by the
//! complete byte form of other OWIDs covered by the signature, and signs it
//! with the ECDSA NIST P-256 private key of the creator. The 64 byte
//! signature completes the OWID, and creating and signing are one step, so
//! an OWID that exists is always signed and never changes afterwards.
//!
//! ## How an OWID comes into being
//!
//! An OWID is only worth anything because it is signed, so this crate does
//! not let one exist in an unsigned state. There are exactly two ways an
//! instance reaches calling code.
//!
//! 1. [`Owid::from_base64`] or [`Owid::from_byte_array`] reads a complete
//!    serialized OWID, and [`Owid::read_from_prefix`] reads one from the
//!    front of a buffer that carries more after it. Bytes that are not an
//!    OWID are an ordinary outcome, so the answer is a [`ParseError`]
//!    naming the reason with a [`ParseStatus`], rather than anything
//!    exceptional.
//! 2. [`Creator::create`] builds and signs one in a single step, owning
//!    the version, the domain, the date and the signature. The payload may
//!    be anything that becomes bytes.
//!
//! Whether the bytes are an OWID and whether its signature is genuine are
//! two questions with two answers. A successful read says nothing about the
//! signature, and [`Owid::verify_status_with_public_key`] answers the
//! second with a [`SignatureStatus`] that keeps a signature that does not
//! match apart from a check that could not be made at all.
//!
//! ## Example
//!
//! ```
//! use owid::{Creator, Crypto, Owid};
//!
//! // The creator operates a domain and holds the signing keys.
//! let crypto = Crypto::new();
//! let creator = Creator::new("example.com", crypto.clone()).unwrap();
//!
//! // Create and sign an OWID with a payload.
//! let owid = creator.create("Hello World").unwrap();
//!
//! // Serialize to base 64 for storage or transmission.
//! let encoded = owid.as_base64().unwrap();
//!
//! // Later, or elsewhere, decode and verify with the creator public key.
//! let copy = Owid::from_base64(&encoded).unwrap();
//! let public_pem = crypto.public_key_pem().unwrap();
//! assert!(copy.verify_with_public_key(&public_pem, &[]).unwrap());
//! ```
//!
//! ## Features
//!
//! The core crate has no network access and compiles for WebAssembly
//! targets such as `wasm32-wasip1`.
//!
//! - `fetch` adds [`Owid::verify`] which retrieves the creator public key
//!   over HTTP from the well known end point and caches it.
//! - `endpoints` adds helpers for hosting the well known end points required
//!   of an OWID creator.

#![warn(missing_docs)]

mod creator;
mod crypto;
mod error;
mod io;
mod owid;
mod parse;
mod status;
mod version;

#[cfg(feature = "endpoints")]
pub mod endpoints;

#[cfg(feature = "fetch")]
mod fetch;

pub use creator::{Configuration, Creator};
pub use crypto::Crypto;
pub use error::{Error, Result};
pub use owid::Owid;
pub use parse::{ParseDetail, ParseError};
pub use status::{ParseStatus, SignatureStatus};
pub use version::Version;

#[cfg(feature = "fetch")]
pub use fetch::public_key_url;

/// The length of an OWID signature in bytes. The ECDSA P-256 signature is
/// the 32 byte r value followed by the 32 byte s value.
pub const SIGNATURE_LENGTH: usize = 64;

/// The examples in the README are compiled and run as documentation tests
/// with the features they need, so the documented way to use this crate can
/// not quietly stop working. In another port the README example had already
/// stopped compiling and nothing noticed.
#[cfg(all(doctest, feature = "fetch", feature = "endpoints"))]
#[doc = include_str!("../README.md")]
struct ReadmeExamples;

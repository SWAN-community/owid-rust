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
//! ## Signing
//!
//! The signing algorithm generates a SHA-256 digest of the OWID data
//! structure without the signature field, optionally followed by the
//! complete byte form of other OWIDs covered by the signature, and signs it
//! with the ECDSA NIST P-256 private key of the creator. The 64 byte
//! signature completes the OWID, which is then immutable.
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
//! let owid = creator.sign_string("Hello World").unwrap();
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
mod version;

#[cfg(feature = "endpoints")]
pub mod endpoints;

#[cfg(feature = "fetch")]
mod fetch;

pub use creator::{Configuration, Creator};
pub use crypto::Crypto;
pub use error::{Error, Result};
pub use owid::Owid;
pub use version::Version;

#[cfg(feature = "fetch")]
pub use fetch::public_key_url;

/// The length of an OWID signature in bytes. The ECDSA P-256 signature is
/// the 32 byte r value followed by the 32 byte s value.
pub const SIGNATURE_LENGTH: usize = 64;

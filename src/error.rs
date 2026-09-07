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

use std::fmt;

/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur when creating, signing, serializing, or verifying
/// OWIDs.
///
/// Reading an OWID from bytes that came from outside answers with a
/// [`crate::ParseError`] instead, because data that is not an OWID is an
/// ordinary outcome there rather than a fault in the program.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The version byte is not one supported by this implementation.
    UnsupportedVersion(u8),
    /// The signature is not exactly the required number of bytes.
    InvalidSignatureLength(usize),
    /// The domain is empty, or contains a null character which would
    /// conflict with the null terminated string encoding.
    InvalidDomain(String),
    /// The domain supplied is longer than the published maximum length of
    /// a domain name, so it is refused when it is supplied rather than
    /// serialized into an OWID this crate would then refuse to read. The
    /// same field arriving over long in a buffer being read is
    /// [`crate::ParseStatus::InvalidDomainEncoding`] instead.
    DomainTooLong,
    /// The date can not be represented in the encoding used by the version.
    DateOutOfRange,
    /// The payload is larger than the unsigned 32 bit length prefix allows.
    PayloadTooLarge(usize),
    /// The OWID is structurally valid, but this implementation could not
    /// reserve the bytes needed to own or serialize it.
    ImplementationCapacityExceeded {
        /// The number of bytes the operation attempted to reserve.
        required: usize,
    },
    /// A key could not be imported, exported, or used. The string contains
    /// the underlying error message.
    Key(String),
    /// The crypto instance can not be used for the operation requested. For
    /// example, an attempt to sign with a verify only instance.
    KeyMissing(&'static str),
    /// The format parameter for the public key end point was not one of the
    /// valid values "spki" or "pkcs".
    InvalidKeyFormat(String),
    /// An HTTP request to a well known end point failed, or was answered
    /// without the key in force at the OWID's date. The string contains the
    /// underlying error message.
    /// Only returned when the `fetch` feature is enabled, by the transport
    /// that made the request or by this crate reading the answer.
    Http(String),
    /// Bytes offered to be read were not an OWID.
    ///
    /// Reading answers with a [`crate::ParseError`] of its own, and this
    /// carries one so that a caller whose own functions return this type
    /// can use `?` on a read as well as on the rest of the crate.
    Parse(crate::ParseError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnsupportedVersion(v) => {
                write!(f, "OWID version '{v}' not supported")
            }
            Error::InvalidSignatureLength(l) => write!(
                f,
                "signature length '{l}' not compatible with '{}' OWID \
                 signature length",
                crate::SIGNATURE_LENGTH
            ),
            Error::InvalidDomain(d) => write!(f, "domain '{d}' is not valid"),
            Error::DomainTooLong => write!(
                f,
                "domain field exceeds the '{}' character maximum",
                crate::io::MAXIMUM_DOMAIN_LENGTH
            ),
            Error::DateOutOfRange => write!(
                f,
                "date can not be stored in the encoding for the OWID version"
            ),
            Error::PayloadTooLarge(l) => {
                write!(f, "payload length '{l}' exceeds the unsigned 32 bit limit")
            }
            Error::ImplementationCapacityExceeded { required } => write!(
                f,
                "OWID requires '{required}' bytes beyond this implementation's capacity"
            ),
            Error::Key(e) => write!(f, "key operation failed because {e}"),
            Error::KeyMissing(o) => {
                write!(f, "instance of Crypto cannot be used to {o}")
            }
            Error::InvalidKeyFormat(v) => write!(
                f,
                "format parameter 'spki' or 'pkcs' must be provided, \
                 received '{v}'"
            ),
            Error::Http(e) => write!(f, "HTTP request failed because {e}"),
            Error::Parse(e) => write!(f, "bytes are not an OWID because {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Parse(e) => Some(e),
            _ => None,
        }
    }
}

impl From<crate::ParseError> for Error {
    fn from(e: crate::ParseError) -> Self {
        Error::Parse(e)
    }
}

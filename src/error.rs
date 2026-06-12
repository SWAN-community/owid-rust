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

/// Errors that can occur when creating, reading, signing, or verifying OWIDs.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The version byte is not one supported by this implementation.
    UnsupportedVersion(u8),
    /// The signature is not exactly the required number of bytes.
    InvalidSignatureLength(usize),
    /// The buffer ended before all the expected fields were read.
    UnexpectedEndOfBuffer,
    /// The base 64 string could not be decoded.
    Base64(base64::DecodeError),
    /// The domain is empty, or contains a null character which would
    /// conflict with the null terminated string encoding.
    InvalidDomain(String),
    /// The domain bytes read from the buffer are not valid UTF-8.
    InvalidDomainEncoding,
    /// The date can not be represented in the encoding used by the version.
    DateOutOfRange,
    /// The payload is larger than the unsigned 32 bit length prefix allows.
    PayloadTooLarge(usize),
    /// A key could not be imported, exported, or used. The string contains
    /// the underlying error message.
    Key(String),
    /// The crypto instance can not be used for the operation requested. For
    /// example, an attempt to sign with a verify only instance.
    KeyMissing(&'static str),
    /// The format parameter for the public key end point was not one of the
    /// valid values "spki" or "pkcs".
    InvalidKeyFormat(String),
    /// An HTTP request to a well known end point failed. The string contains
    /// the underlying error message. Only returned when the `fetch` feature
    /// is enabled.
    Http(String),
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
            Error::UnexpectedEndOfBuffer => {
                write!(f, "buffer ended before the OWID was complete")
            }
            Error::Base64(e) => write!(f, "base 64 decoding failed because {e}"),
            Error::InvalidDomain(d) => write!(f, "domain '{d}' is not valid"),
            Error::InvalidDomainEncoding => {
                write!(f, "domain bytes are not valid UTF-8")
            }
            Error::DateOutOfRange => write!(
                f,
                "date can not be stored in the encoding for the OWID version"
            ),
            Error::PayloadTooLarge(l) => {
                write!(f, "payload length '{l}' exceeds the unsigned 32 bit limit")
            }
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
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Base64(e) => Some(e),
            _ => None,
        }
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e)
    }
}

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
use std::str::FromStr;

use base64::engine::general_purpose::GeneralPurpose;
use base64::engine::{DecodePaddingMode, GeneralPurposeConfig};
use base64::{alphabet, engine::Engine as _};
use chrono::{DateTime, Utc};

use crate::crypto::Crypto;
use crate::error::{Error, Result};
use crate::io;
use crate::parse;
use crate::parse::ParseError;
use crate::status::{ParseStatus, SignatureStatus};
use crate::version::Version;

/// Base 64 engine that writes the standard alphabet with padding, and reads
/// strings with or without padding. Encoded OWIDs occur both with and
/// without padding, so reading must accept both.
const BASE64: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// OWID structure which can be used as a node in a tree.
///
/// An OWID records that the processor operating the domain handled the
/// payload, and any other OWIDs covered by the signature, at the date and
/// time given.
///
/// An OWID is only worth anything because it is signed, so one cannot exist
/// in an unsigned state. There are exactly two ways an instance reaches
/// calling code, being a successful read of a complete serialized OWID
/// through [`Owid::from_base64`] or [`Owid::from_byte_array`], and a
/// [`crate::Creator`] creating and signing one in a single step. The fields
/// are private and there is no public constructor, so no half built OWID
/// can be held or passed on. An unsigned one is indistinguishable from a
/// signed one to the code downstream of it, and the difference only
/// surfaces later when a verification fails somewhere nobody is watching.
///
/// The state is read only for the same reason. The signature covers the
/// fields as they arrived, so a caller that could change one would hold
/// something whose signature no longer describes it. The byte accessors
/// hand out shared borrows, which the compiler will not let anyone write
/// through, so no copy is made to protect the OWID from its own reader.
///
/// ```compile_fail
/// use owid::Owid;
/// use chrono::Utc;
///
/// // No public constructor, and the fields are private, so there is no
/// // way to assemble one from outside the crate.
/// let owid = Owid {
///     version: owid::Version::Version3,
///     domain: "example.com".to_owned(),
///     date: Utc::now(),
///     payload: Vec::new(),
///     signature: Vec::new(),
/// };
/// ```
///
/// ```compile_fail
/// use owid::{Creator, Crypto};
///
/// let creator = Creator::new("example.com", Crypto::new()).unwrap();
/// let mut owid = creator.create("Hello World").unwrap();
///
/// // No field can be set or rebound from outside either, so nothing can
/// // hold an OWID whose signature no longer describes it.
/// owid.domain = "elsewhere.com".to_owned();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owid {
    version: Version,
    domain: String,
    date: DateTime<Utc>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl Owid {
    /// Builds an instance from fields that have already been read or
    /// signed. Crate private, because every public route to an OWID runs
    /// through a complete parse or a creator that signs.
    pub(crate) fn from_parts(
        version: Version,
        domain: String,
        date: DateTime<Utc>,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Owid {
            version,
            domain,
            date,
            payload,
            signature,
        }
    }

    /// Replaces the signature. Crate private, and used only by the creator
    /// between building the fields and returning the finished OWID, so the
    /// unsigned moment never leaves the crate.
    pub(crate) fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }

    /// The byte version of the OWID.
    pub fn version(&self) -> Version {
        self.version
    }

    /// The domain associated with the creator.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The date and time to the nearest minute in UTC of the creation.
    pub fn date(&self) -> DateTime<Utc> {
        self.date
    }

    /// The bytes that form the payload.
    ///
    /// A shared borrow rather than a copy, because the compiler will not
    /// let a caller write through it, so nothing has to be copied to keep
    /// the OWID from being changed by whoever reads it.
    ///
    /// ```compile_fail
    /// use owid::{Creator, Crypto};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let owid = creator.create("Hello World").unwrap();
    ///
    /// // The borrow is read only, so this does not compile.
    /// owid.payload()[0] = 0;
    /// ```
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The signature for this OWID and any others provided when it was
    /// created. See [`Owid::payload`] on why this is a borrow.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Reads an OWID from a base 64 encoded string, with or without
    /// padding.
    ///
    /// Bytes offered to this crate come from outside, so data that is not
    /// an OWID is an ordinary outcome and is reported as a [`ParseError`]
    /// naming the reason rather than as anything exceptional.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] carrying [`ParseStatus::MissingInput`] for
    /// an empty string, [`ParseStatus::InvalidBase64`] for a string that is
    /// not base 64, or any status from [`Owid::from_byte_array`].
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto, Owid};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let original = creator.create("Hello World").unwrap();
    /// let copy = Owid::from_base64(&original.as_base64().unwrap()).unwrap();
    /// assert_eq!(original.payload(), copy.payload());
    /// ```
    pub fn from_base64(value: &str) -> std::result::Result<Self, ParseError> {
        if value.is_empty() {
            return Err(ParseError::new(ParseStatus::MissingInput, None));
        }
        match BASE64.decode(value) {
            // The decode error names a position in the input, so it is not
            // carried forward. What a caller can act on is that the string
            // was not base 64.
            Err(_) => Err(ParseError::new(ParseStatus::InvalidBase64, None)),
            Ok(buffer) => Owid::from_byte_array(&buffer),
        }
    }

    /// Reads an OWID from its binary form. The buffer must hold exactly one
    /// complete OWID, so bytes after the signature are refused, and the one
    /// byte marker standing for a node that is not there is
    /// [`ParseStatus::AbsentNode`] rather than an OWID. Where a buffer
    /// carries a run of frames, or an OWID followed by something else, use
    /// [`Owid::read_from_prefix`] instead.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] whose [`ParseError::status`] names the
    /// reason. Neither variable length field is read beyond what the format
    /// allows, so a buffer that declares a payload it does not carry, or
    /// that never terminates its domain, is refused without the work
    /// growing with the size of the buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Owid, ParseStatus};
    ///
    /// let error = Owid::from_byte_array(&[9, 9, 9]).unwrap_err();
    /// assert_eq!(error.status(), ParseStatus::UnsupportedVersion);
    /// ```
    pub fn from_byte_array(buffer: &[u8]) -> std::result::Result<Self, ParseError> {
        parse::parse_exact(buffer)
    }

    /// Reads one frame from the front of a buffer that carries more than
    /// one thing, returning what it held with the bytes that follow.
    ///
    /// Use this where OWIDs arrive one after another, or where an OWID sits
    /// inside a larger format. It differs from [`Owid::from_byte_array`] in
    /// two places.
    ///
    /// It requires only the declared payload and the signature to be
    /// present and says nothing about what comes after them, because what
    /// comes after them may be the next frame rather than rubbish. A
    /// declared payload running past the bytes supplied is
    /// [`ParseStatus::UnexpectedEnd`], being data that stopped early, so a
    /// caller reading a source that is still arriving can wait for more
    /// bytes rather than give up.
    ///
    /// A frame may also hold the one byte marker standing for a node that
    /// is not there, which this steps over, handing back `None` with the
    /// bytes after it so the next frame can be read.
    /// [`ParseStatus::of_frame`] names that outcome
    /// [`ParseStatus::AbsentNode`]. No OWID is handed back for a marker,
    /// because it carries no signature and nothing that could be mistaken
    /// for an identifier should reach a caller.
    ///
    /// The bytes that follow are returned rather than a count of the bytes
    /// used, because reading the next envelope is what a caller does next
    /// and the remainder is what that needs, with the borrow checker
    /// keeping the arithmetic honest. `buffer.len() - rest.len()` is the
    /// length of the envelope where a caller wants the number. This is the
    /// shape `zerocopy` uses for `read_from_prefix`.
    ///
    /// Nothing is consumed when this fails, since the remainder is handed
    /// back only on success, so a failed read cannot leave a caller part
    /// way through an envelope.
    ///
    /// # Errors
    ///
    /// Returns a [`ParseError`] whose [`ParseError::status`] names the
    /// reason, from the same vocabulary as the whole buffer read.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto, Owid};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let mut buffer = Vec::new();
    /// for payload in ["first", "second"] {
    ///     creator.create(payload).unwrap().to_buffer(&mut buffer).unwrap();
    /// }
    ///
    /// let mut rest = buffer.as_slice();
    /// let mut payloads = Vec::new();
    /// while !rest.is_empty() {
    ///     let (owid, remainder) = Owid::read_from_prefix(rest).unwrap();
    ///     // None where the frame said the node is not there.
    ///     if let Some(owid) = owid {
    ///         payloads.push(owid.payload_as_string());
    ///     }
    ///     rest = remainder;
    /// }
    /// assert_eq!(payloads, ["first", "second"]);
    /// ```
    pub fn read_from_prefix(
        buffer: &[u8],
    ) -> std::result::Result<(Option<Self>, &[u8]), ParseError> {
        parse::parse_prefix(buffer)
    }

    /// Returns the OWID as a byte array.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DomainTooLong`] if the domain is longer than the
    /// maximum a domain name may be, or other errors if the fields can not
    /// be encoded.
    pub fn as_byte_array(&self) -> Result<Vec<u8>> {
        let capacity = self.encoded_len(true)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| Error::ImplementationCapacityExceeded { required: capacity })?;
        self.to_buffer(&mut buffer)?;
        Ok(buffer)
    }

    /// Returns the OWID as a base 64 encoded string.
    ///
    /// # Errors
    ///
    /// See [`Owid::as_byte_array`].
    pub fn as_base64(&self) -> Result<String> {
        Ok(BASE64.encode(self.as_byte_array()?))
    }

    /// Appends the OWID, including the signature, to the buffer provided.
    ///
    /// # Errors
    ///
    /// See [`Owid::as_byte_array`].
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> Result<()> {
        self.to_buffer_no_signature(buffer)?;
        io::write_signature(buffer, &self.signature)
    }

    /// Writes the one byte marker that says a node is not there, which is
    /// how a byte array carries an optional OWID that is absent.
    ///
    /// Reading a frame, [`Owid::read_from_prefix`] steps over a marker and
    /// hands back `None` with the bytes after it, so a caller walking a run
    /// of frames can tell a node that is absent from one that is malformed
    /// and carry on to the next. Reading a buffer that should hold one
    /// OWID, [`Owid::from_byte_array`] reports
    /// [`ParseStatus::AbsentNode`], because a marker on its own is not an
    /// identifier. No OWID is handed back for a marker either way, since it
    /// carries no signature.
    pub fn empty_to_buffer(buffer: &mut Vec<u8>) {
        io::write_byte(buffer, Version::Empty.as_byte());
    }

    /// Appends the fields other than the signature to the buffer. This is
    /// the data over which the signature is calculated, so a domain longer
    /// than a domain name may be is refused here, before any signature is
    /// computed over it.
    pub(crate) fn to_buffer_no_signature(&self, buffer: &mut Vec<u8>) -> Result<()> {
        io::write_byte(buffer, self.version.as_byte());
        io::write_domain(buffer, &self.domain)?;
        io::write_date(buffer, &self.date, self.version)?;
        io::write_byte_array(buffer, &self.payload)
    }

    /// Builds the byte array used for signing and verification. Contains the
    /// fields of this OWID without the signature, followed by the complete
    /// byte form of each of the others in the order provided.
    pub(crate) fn data_for_crypto(&self, others: &[&Owid]) -> Result<Vec<u8>> {
        let mut capacity = self.encoded_len(false)?;
        for other in others {
            capacity = capacity.checked_add(other.encoded_len(true)?).ok_or(
                Error::ImplementationCapacityExceeded {
                    required: usize::MAX,
                },
            )?;
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(capacity)
            .map_err(|_| Error::ImplementationCapacityExceeded { required: capacity })?;
        self.to_buffer_no_signature(&mut buffer)?;
        for other in others {
            other.to_buffer(&mut buffer)?;
        }
        Ok(buffer)
    }

    /// The exact number of bytes written for this OWID.
    fn encoded_len(&self, include_signature: bool) -> Result<usize> {
        if self.payload.len() > u32::MAX as usize {
            return Err(Error::PayloadTooLarge(self.payload.len()));
        }
        if include_signature && self.signature.len() != crate::SIGNATURE_LENGTH {
            return Err(Error::InvalidSignatureLength(self.signature.len()));
        }
        let date_len = match self.version {
            Version::Version1 => 2,
            Version::Version2 | Version::Version3 => 4,
            other => return Err(Error::UnsupportedVersion(other.as_byte())),
        };
        let lengths = [
            1,
            self.domain.len(),
            1,
            date_len,
            4,
            self.payload.len(),
            if include_signature {
                crate::SIGNATURE_LENGTH
            } else {
                0
            },
        ];
        lengths.into_iter().try_fold(0usize, |total, length| {
            total
                .checked_add(length)
                .ok_or(Error::ImplementationCapacityExceeded {
                    required: usize::MAX,
                })
        })
    }

    /// The payload interpreted as a string. Bytes that are not valid UTF-8
    /// are replaced with the replacement character.
    pub fn payload_as_string(&self) -> String {
        String::from_utf8_lossy(&self.payload).into_owned()
    }

    /// The payload as lower case hexadecimal for display purposes.
    pub fn payload_as_printable(&self) -> String {
        self.payload.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The payload as a base 64 encoded string.
    pub fn payload_as_base64(&self) -> String {
        BASE64.encode(&self.payload)
    }

    /// Returns the number of complete minutes that have elapsed since the
    /// OWID was created. The granularity is to the nearest minute.
    pub fn age_minutes(&self) -> i64 {
        (Utc::now() - self.date).num_minutes()
    }

    /// Verifies this OWID, and any others that were included when it was
    /// signed, using the crypto instance provided.
    ///
    /// Pass an empty slice for `others` when the OWID was signed on its own.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyMissing`] if the crypto instance can not verify,
    /// or other errors if the fields can not be encoded.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto};
    ///
    /// let crypto = Crypto::new();
    /// let creator = Creator::new("example.com", crypto.clone()).unwrap();
    /// let owid = creator.create("Hello World").unwrap();
    /// assert!(owid.verify_with_crypto(&crypto, &[]).unwrap());
    /// ```
    pub fn verify_with_crypto(&self, crypto: &Crypto, others: &[&Owid]) -> Result<bool> {
        let data = self.data_for_crypto(others)?;
        crypto.verify_byte_array(&data, &self.signature)
    }

    /// Verifies this OWID, and any others that were included when it was
    /// signed, using the public key in SPKI PEM form provided.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Key`] if the PEM is not a valid public key, or any
    /// error from [`Owid::verify_with_crypto`].
    pub fn verify_with_public_key(&self, public_pem: &str, others: &[&Owid]) -> Result<bool> {
        let crypto = Crypto::new_verify_only(public_pem)?;
        self.verify_with_crypto(&crypto, others)
    }

    /// The same check as [`Owid::verify_with_crypto`], answered with the
    /// status that names the outcome.
    ///
    /// Use this where the difference between a signature that does not
    /// match and a check that could not be made matters, because only
    /// [`SignatureStatus::Invalid`] means the identifier should be
    /// distrusted.
    pub fn verify_status_with_crypto(&self, crypto: &Crypto, others: &[&Owid]) -> SignatureStatus {
        SignatureStatus::of(self.verify_with_crypto(crypto, others))
    }

    /// The same check as [`Owid::verify_with_public_key`], answered with
    /// the status that names the outcome.
    ///
    /// A PEM that cannot be read is [`SignatureStatus::InvalidKey`] and
    /// never [`SignatureStatus::Invalid`], so a key served in a form this
    /// crate cannot read reads as the operational fault it is rather than
    /// as an attack.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto, SignatureStatus};
    ///
    /// let crypto = Crypto::new();
    /// let creator = Creator::new("example.com", crypto.clone()).unwrap();
    /// let owid = creator.create("Hello World").unwrap();
    ///
    /// let pem = crypto.public_key_pem().unwrap();
    /// assert_eq!(
    ///     owid.verify_status_with_public_key(&pem, &[]),
    ///     SignatureStatus::Valid);
    /// assert_eq!(
    ///     owid.verify_status_with_public_key("not a PEM", &[]),
    ///     SignatureStatus::InvalidKey);
    /// ```
    pub fn verify_status_with_public_key(
        &self,
        public_pem: &str,
        others: &[&Owid],
    ) -> SignatureStatus {
        SignatureStatus::of(self.verify_with_public_key(public_pem, others))
    }
}

impl fmt::Display for Owid {
    /// Formats the OWID as a base 64 string, or the text of the error if it
    /// can not be encoded.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_base64() {
            Ok(value) => write!(f, "{value}"),
            Err(e) => write!(f, "{e}"),
        }
    }
}

impl FromStr for Owid {
    type Err = ParseError;

    fn from_str(s: &str) -> std::result::Result<Self, ParseError> {
        Owid::from_base64(s)
    }
}

impl TryFrom<&[u8]> for Owid {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, ParseError> {
        Owid::from_byte_array(value)
    }
}

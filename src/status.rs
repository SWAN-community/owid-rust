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

//! The named reasons a read of an OWID, and a check of its signature,
//! finished the way they did. The names are the cross language vocabulary
//! shared by the OWID implementations, so a failure means the same thing
//! whichever language read the bytes.

use std::fmt;

use crate::error::Error;
use crate::parse::ParseError;

/// Why reading an OWID succeeded or failed.
///
/// An OWID is read from whatever a caller was handed, which on a public end
/// point means anything at all, so malformed data is an ordinary outcome
/// rather than an exceptional one and every value here is a normal result.
///
/// The cross language vocabulary also contains `InvalidInputType`, for a
/// caller passing something that is not text or bytes. Rust has no counter
/// part because the compiler refuses that call, so the variant is left out
/// rather than given a path it could never be reached by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseStatus {
    /// The bytes form a structurally valid OWID. It says nothing about the
    /// signature, which is a separate question with a separate answer in
    /// [`SignatureStatus`].
    Parsed,
    /// Nothing was supplied to read, being an empty string or an empty
    /// buffer.
    MissingInput,
    /// The string is not valid base 64, so there are no bytes to read.
    InvalidBase64,
    /// The first byte names a version this implementation does not know.
    /// The empty marker written by [`crate::Owid::empty_to_buffer`] is
    /// reported this way as well, because a marker saying an OWID is absent
    /// is not itself an OWID.
    UnsupportedVersion,
    /// The data stopped in the middle of a field, before the declared
    /// payload length was even read. Distinct from [`Self::ByteCountMismatch`],
    /// which is a declaration that disagrees with the bytes that follow it.
    UnexpectedEnd,
    /// The creator domain has no terminator within the published maximum
    /// length of a domain name, or the bytes it holds are not valid UTF-8.
    InvalidDomainEncoding,
    /// The declared payload byte count disagrees with the bytes actually
    /// present. Checked before anything is sized by the declaration, so a
    /// sender cannot make a reader reserve memory by claiming a large
    /// payload it did not send.
    ByteCountMismatch,
    /// The envelope is structurally consistent but larger than this build
    /// can hold or reserve. Not a fault in the data, and deliberately apart
    /// from the data being wrong, because the same bytes may be readable on
    /// a machine with a wider pointer or more memory.
    ///
    /// No test produces one. A declared count is at most the four byte
    /// field allows, which every 64 bit `usize` can hold, so this needs
    /// either a target whose pointer is narrower than the count or an
    /// allocator that refuses the reservation, and neither can be asked for
    /// on the builds the suite runs on. The mapping is still checked, in
    /// the tests below, because the count has to be refused rather than
    /// treated as data that is wrong.
    ImplementationCapacityExceeded,
    /// A fallback for the genuinely unclassified, not a substitute for
    /// naming a failure that is already understood.
    ///
    /// Nothing produces one, so no test can. Every way an envelope can be
    /// wrong is named by one of the statuses above, and the single place
    /// this is raised is a check that the byte count comparison already
    /// makes redundant, kept so that a later change to that arithmetic
    /// cannot quietly start accepting bytes after the envelope.
    MalformedEnvelope,
}

impl ParseStatus {
    /// The status of a read, being [`Self::Parsed`] when it worked and the
    /// reason it did not otherwise.
    ///
    /// A [`Result`] already says whether the read worked and holds the OWID
    /// only when it did, so this exists for the third fact, which is the
    /// named reason, in the one place where success has no error to carry
    /// it. It takes the outcome of either read, the framed one handing back
    /// the remaining bytes alongside the OWID.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto, Owid, ParseStatus};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let encoded = creator.create("Hello World").unwrap();
    /// let encoded = encoded.as_base64().unwrap();
    ///
    /// let result = Owid::from_base64(&encoded);
    /// assert_eq!(ParseStatus::of(&result), ParseStatus::Parsed);
    ///
    /// let result = Owid::from_base64("not base 64!");
    /// assert_eq!(ParseStatus::of(&result), ParseStatus::InvalidBase64);
    /// ```
    pub fn of<T>(result: &Result<T, ParseError>) -> ParseStatus {
        match result {
            Ok(_) => ParseStatus::Parsed,
            Err(e) => e.status(),
        }
    }

    /// The cross language name of the status, borrowed rather than built,
    /// which is what [`fmt::Display`] writes.
    pub fn as_str(self) -> &'static str {
        match self {
            ParseStatus::Parsed => "Parsed",
            ParseStatus::MissingInput => "MissingInput",
            ParseStatus::InvalidBase64 => "InvalidBase64",
            ParseStatus::UnsupportedVersion => "UnsupportedVersion",
            ParseStatus::UnexpectedEnd => "UnexpectedEnd",
            ParseStatus::InvalidDomainEncoding => "InvalidDomainEncoding",
            ParseStatus::ByteCountMismatch => "ByteCountMismatch",
            ParseStatus::ImplementationCapacityExceeded => "ImplementationCapacityExceeded",
            ParseStatus::MalformedEnvelope => "MalformedEnvelope",
        }
    }
}

impl fmt::Display for ParseStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of asking whether the signature on an OWID is genuine.
///
/// Only two of these say anything about the signature itself. The rest say
/// the question could not be answered, which is a different thing and must
/// never be reported as a forgery. A key that cannot be fetched, a key that
/// cannot be decoded, or a provider that fails leaves the signature
/// unjudged, and a caller acting on "invalid" would reject good identifiers
/// during an outage.
///
/// On 30 August 2026 the key end points served PEM that a strict parser
/// rejects and every offline verification against them failed, while the
/// keys and the identifiers were both fine. Reported as
/// [`Self::InvalidKey`] that reads as the operational fault it was, whereas
/// reported as [`Self::Invalid`] it would have read as an attack.
///
/// The cross language names for the first two are `SignatureValid` and
/// `SignatureInvalid`, which is what [`fmt::Display`] writes, because the
/// enum already carries the word signature in Rust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignatureStatus {
    /// The signature is genuine for this data and this key.
    Valid,
    /// The signature is well formed and does not match. The only status
    /// that means the identifier should be distrusted.
    Invalid,
    /// A signature field of the wrong length reached verification directly.
    /// Truncation in raw external input is a parse
    /// [`ParseStatus::UnexpectedEnd`] or [`ParseStatus::ByteCountMismatch`]
    /// instead, because there the envelope never formed.
    ///
    /// Nothing in this crate can produce it today, because every OWID that
    /// exists carries a signature of the right length, having come from a
    /// read that checked it or a creation that made it. It is kept because
    /// a length failure must never be mapped to [`Self::Invalid`] if a
    /// later change lets one through.
    InvalidSignatureLength,
    /// No key could be obtained, so the signature was never examined.
    ///
    /// Reached through the `fetch` feature, where the key comes from the
    /// creator domain over HTTP and the request can fail. Every
    /// [`crate::Crypto`] this crate can build carries a verifying key, so
    /// a key held in hand is never missing.
    KeyUnavailable,
    /// Key material arrived but cannot be decoded, imported, or used as the
    /// type required. The fault is in the key, not in the identifier.
    InvalidKey,
    /// The data to check the signature over is larger than this build can
    /// reserve, so the check could not be attempted. No test produces one,
    /// for the reason given on
    /// [`ParseStatus::ImplementationCapacityExceeded`], and the mapping is
    /// checked in the tests below.
    ImplementationCapacityExceeded,
    /// The check could not be completed for a reason that is not the
    /// identifier's fault. Nothing in this crate produces it today for the
    /// same reason as [`Self::InvalidSignatureLength`], and it is the
    /// fallback that keeps any later failure away from [`Self::Invalid`].
    VerificationError,
}

impl SignatureStatus {
    /// Turns the outcome of a verification into the status that names it.
    ///
    /// Every error that is not the signature failing to match is mapped to
    /// a status that says the signature was not judged, so an outage can
    /// never be reported as a forgery.
    pub(crate) fn of(result: crate::error::Result<bool>) -> SignatureStatus {
        match result {
            Ok(true) => SignatureStatus::Valid,
            Ok(false) => SignatureStatus::Invalid,
            Err(Error::InvalidSignatureLength(_)) => SignatureStatus::InvalidSignatureLength,
            // No key to work with, either because the instance holds none
            // for this operation or because fetching one failed.
            Err(Error::KeyMissing(_)) | Err(Error::Http(_)) => SignatureStatus::KeyUnavailable,
            // Key material arrived and could not be used.
            Err(Error::Key(_)) | Err(Error::InvalidKeyFormat(_)) => SignatureStatus::InvalidKey,
            Err(Error::ImplementationCapacityExceeded { .. }) => {
                SignatureStatus::ImplementationCapacityExceeded
            }
            Err(_) => SignatureStatus::VerificationError,
        }
    }

    /// The cross language name of the status, borrowed rather than built,
    /// which is what [`fmt::Display`] writes.
    pub fn as_str(self) -> &'static str {
        match self {
            SignatureStatus::Valid => "SignatureValid",
            SignatureStatus::Invalid => "SignatureInvalid",
            SignatureStatus::InvalidSignatureLength => "InvalidSignatureLength",
            SignatureStatus::KeyUnavailable => "KeyUnavailable",
            SignatureStatus::InvalidKey => "InvalidKey",
            SignatureStatus::ImplementationCapacityExceeded => "ImplementationCapacityExceeded",
            SignatureStatus::VerificationError => "VerificationError",
        }
    }
}

impl fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owid::Owid;

    /// The names are the cross language vocabulary, so a status written to
    /// a log or compared across implementations reads the same everywhere.
    #[test]
    fn parse_status_names_are_the_cross_language_ones() {
        assert_eq!(ParseStatus::Parsed.to_string(), "Parsed");
        assert_eq!(
            ParseStatus::ByteCountMismatch.to_string(),
            "ByteCountMismatch"
        );
        assert_eq!(
            ParseStatus::ImplementationCapacityExceeded.to_string(),
            "ImplementationCapacityExceeded"
        );
    }

    /// The signature names keep the word signature, which the Rust variant
    /// names leave to the enum.
    #[test]
    fn signature_status_names_are_the_cross_language_ones() {
        assert_eq!(SignatureStatus::Valid.to_string(), "SignatureValid");
        assert_eq!(SignatureStatus::Invalid.to_string(), "SignatureInvalid");
        assert_eq!(SignatureStatus::InvalidKey.to_string(), "InvalidKey");
    }

    /// The outcomes that must produce each signature status.
    ///
    /// The match has no wildcard, so a member added to the vocabulary
    /// without a decision about how it is reached will not compile.
    fn outcomes_for(status: SignatureStatus) -> Vec<crate::error::Result<bool>> {
        match status {
            SignatureStatus::Valid => vec![Ok(true)],
            SignatureStatus::Invalid => vec![Ok(false)],
            SignatureStatus::InvalidSignatureLength => {
                vec![Err(Error::InvalidSignatureLength(63))]
            }
            SignatureStatus::KeyUnavailable => vec![
                Err(Error::KeyMissing("verify a signature")),
                Err(Error::Http("connection refused".to_owned())),
            ],
            SignatureStatus::InvalidKey => vec![
                Err(Error::Key("bad PEM".to_owned())),
                Err(Error::InvalidKeyFormat("xyz".to_owned())),
            ],
            SignatureStatus::ImplementationCapacityExceeded => {
                vec![Err(Error::ImplementationCapacityExceeded { required: 1 })]
            }
            SignatureStatus::VerificationError => vec![Err(Error::DateOutOfRange)],
        }
    }

    /// Every member of the signature vocabulary has a case, so none is
    /// silently untested, including the two nothing in this crate can
    /// produce, whose mapping still has to be right. Only a signature that
    /// does not match may be reported as invalid, because anything else
    /// read that way would report an outage as an attack.
    #[test]
    fn every_signature_status_is_mapped_from_the_outcome_that_means_it() {
        for status in [
            SignatureStatus::Valid,
            SignatureStatus::Invalid,
            SignatureStatus::InvalidSignatureLength,
            SignatureStatus::KeyUnavailable,
            SignatureStatus::InvalidKey,
            SignatureStatus::ImplementationCapacityExceeded,
            SignatureStatus::VerificationError,
        ] {
            for outcome in outcomes_for(status) {
                let was_error = outcome.is_err();
                assert_eq!(
                    SignatureStatus::of(outcome),
                    status,
                    "should map to {status}"
                );
                if was_error {
                    assert_ne!(
                        status,
                        SignatureStatus::Invalid,
                        "an error that is not a mismatch must not read as a forgery"
                    );
                    assert_ne!(
                        status,
                        SignatureStatus::Valid,
                        "an error must never read as a genuine signature"
                    );
                }
            }
        }
    }

    /// What has to be read to produce each parse status.
    enum Case {
        /// Bytes that the whole buffer read must answer with the status,
        /// together with what the framed read must answer for the same
        /// bytes. The two agree everywhere except where the whole buffer
        /// read is refusing bytes after the envelope, which is the one
        /// place the two contracts differ.
        Bytes { bytes: Vec<u8>, framed: ParseStatus },
        /// A string offered to the base 64 reader. There is no framed read
        /// of base 64, because a run of envelopes is decoded once and then
        /// walked as bytes.
        Text(&'static str),
        /// A status this crate cannot produce, for the reason recorded on
        /// the member itself.
        CannotBeProduced,
    }

    /// The input that must produce each parse status.
    ///
    /// The match has no wildcard, so a member added to the vocabulary
    /// without a decision about how it is reached will not compile, which
    /// is what stops a status being added and never tested.
    fn case_for(status: ParseStatus) -> Case {
        match status {
            ParseStatus::Parsed => Case::Bytes {
                bytes: signed_envelope(),
                framed: ParseStatus::Parsed,
            },
            ParseStatus::MissingInput => Case::Bytes {
                bytes: Vec::new(),
                framed: ParseStatus::MissingInput,
            },
            ParseStatus::InvalidBase64 => Case::Text("not base 64!"),
            // The empty marker, which says an OWID is absent, is a version
            // this reader does not accept as an envelope.
            ParseStatus::UnsupportedVersion => Case::Bytes {
                bytes: vec![0],
                framed: ParseStatus::UnsupportedVersion,
            },
            ParseStatus::UnexpectedEnd => Case::Bytes {
                bytes: vec![3, b'a', b'b'],
                framed: ParseStatus::UnexpectedEnd,
            },
            ParseStatus::InvalidDomainEncoding => {
                let mut bytes = vec![3, 0xFF, 0xFE, 0];
                bytes.extend_from_slice(&1000u32.to_le_bytes());
                bytes.extend_from_slice(&0u32.to_le_bytes());
                bytes.extend_from_slice(&[0x99; crate::SIGNATURE_LENGTH]);
                Case::Bytes {
                    bytes,
                    framed: ParseStatus::InvalidDomainEncoding,
                }
            }
            // A byte after the signature. The whole buffer read refuses it,
            // because nothing else in a buffer holding one OWID could own
            // it, and the framed read hands it back as the start of
            // whatever comes next.
            ParseStatus::ByteCountMismatch => {
                let mut bytes = signed_envelope();
                bytes.push(0);
                Case::Bytes {
                    bytes,
                    framed: ParseStatus::Parsed,
                }
            }
            ParseStatus::ImplementationCapacityExceeded => Case::CannotBeProduced,
            ParseStatus::MalformedEnvelope => Case::CannotBeProduced,
        }
    }

    /// A complete envelope, signed, so the successful case is a real OWID
    /// rather than bytes shaped like one.
    fn signed_envelope() -> Vec<u8> {
        let creator = crate::Creator::new("test.com", crate::Crypto::new())
            .expect("should create the creator");
        creator
            .create("Hello World")
            .expect("should create")
            .as_byte_array()
            .expect("should serialize")
    }

    /// Every member of the parse vocabulary has a case, so none is silently
    /// untested. The two that cannot be produced say so on the member, and
    /// this holds that claim to account by failing if one of them ever
    /// starts coming back.
    #[test]
    fn every_parse_status_has_a_case() {
        for status in [
            ParseStatus::Parsed,
            ParseStatus::MissingInput,
            ParseStatus::InvalidBase64,
            ParseStatus::UnsupportedVersion,
            ParseStatus::UnexpectedEnd,
            ParseStatus::InvalidDomainEncoding,
            ParseStatus::ByteCountMismatch,
            ParseStatus::ImplementationCapacityExceeded,
            ParseStatus::MalformedEnvelope,
        ] {
            match case_for(status) {
                Case::Bytes { bytes, framed } => {
                    let result = Owid::from_byte_array(&bytes);
                    assert_eq!(
                        ParseStatus::of(&result),
                        status,
                        "reading these bytes should report {status}"
                    );
                    assert_eq!(
                        result.is_ok(),
                        status == ParseStatus::Parsed,
                        "only {} may come with an OWID",
                        ParseStatus::Parsed
                    );
                    let framed_result = Owid::read_from_prefix(&bytes);
                    assert_eq!(
                        ParseStatus::of(&framed_result),
                        framed,
                        "the framed read of these bytes should report {framed}"
                    );
                    assert_eq!(
                        framed_result.is_ok(),
                        framed == ParseStatus::Parsed,
                        "only {} may come with an OWID",
                        ParseStatus::Parsed
                    );
                }
                Case::Text(text) => {
                    let result = Owid::from_base64(text);
                    assert_eq!(
                        ParseStatus::of(&result),
                        status,
                        "reading this string should report {status}"
                    );
                    assert!(result.is_err(), "a failure should hand back no OWID");
                }
                Case::CannotBeProduced => {
                    let mut trailing = signed_envelope();
                    trailing.push(0);
                    for bytes in [Vec::new(), vec![0], signed_envelope(), trailing] {
                        for reported in [
                            ParseStatus::of(&Owid::from_byte_array(&bytes)),
                            ParseStatus::of(&Owid::read_from_prefix(&bytes)),
                        ] {
                            assert_ne!(
                                reported, status,
                                "{status} is documented as one this crate does not produce"
                            );
                        }
                    }
                }
            }
        }
    }
}

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
use crate::owid::Owid;
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
    ImplementationCapacityExceeded,
    /// A fallback for the genuinely unclassified, not a substitute for
    /// naming a failure that is already understood.
    MalformedEnvelope,
}

impl ParseStatus {
    /// The status of a parse outcome, being [`Self::Parsed`] when it worked
    /// and the reason it did not otherwise.
    ///
    /// A [`Result`] already says whether the read worked and holds the OWID
    /// only when it did, so this exists for the third fact, which is the
    /// named reason, in the one place where success has no error to carry
    /// it.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto, Owid, ParseStatus};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let encoded = creator.create_string("Hello World").unwrap();
    /// let encoded = encoded.as_base64().unwrap();
    ///
    /// let result = Owid::from_base64(&encoded);
    /// assert_eq!(ParseStatus::of(&result), ParseStatus::Parsed);
    ///
    /// let result = Owid::from_base64("not base 64!");
    /// assert_eq!(ParseStatus::of(&result), ParseStatus::InvalidBase64);
    /// ```
    pub fn of(result: &Result<Owid, ParseError>) -> ParseStatus {
        match result {
            Ok(_) => ParseStatus::Parsed,
            Err(e) => e.status(),
        }
    }

    /// The cross language name of the status, which is what
    /// [`fmt::Display`] writes.
    pub fn name(self) -> &'static str {
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
        f.write_str(self.name())
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
    KeyUnavailable,
    /// Key material arrived but cannot be decoded, imported, or used as the
    /// type required. The fault is in the key, not in the identifier.
    InvalidKey,
    /// The data to check the signature over is larger than this build can
    /// reserve, so the check could not be attempted.
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

    /// The cross language name of the status, which is what
    /// [`fmt::Display`] writes.
    pub fn name(self) -> &'static str {
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
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// Nothing that is not the signature failing to match may be reported
    /// as an invalid signature, because that would read as an attack when
    /// it is an outage.
    #[test]
    fn only_a_mismatch_is_reported_as_invalid() {
        assert_eq!(SignatureStatus::of(Ok(true)), SignatureStatus::Valid);
        assert_eq!(SignatureStatus::of(Ok(false)), SignatureStatus::Invalid);
        for error in [
            Error::Key("bad PEM".to_owned()),
            Error::KeyMissing("verify a signature"),
            Error::Http("connection refused".to_owned()),
            Error::InvalidKeyFormat("xyz".to_owned()),
            Error::InvalidSignatureLength(63),
            Error::ImplementationCapacityExceeded { required: 1 },
            Error::DateOutOfRange,
        ] {
            let status = SignatureStatus::of(Err(error));
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

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

use chrono::Utc;

use crate::crypto::Crypto;
use crate::error::{Error, Result};
use crate::io::MAXIMUM_DOMAIN_LENGTH;
use crate::owid::Owid;
use crate::version::Version;

/// Configuration for a [`Creator`] where the domain and keys come from
/// settings rather than code.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "endpoints", derive(serde::Serialize, serde::Deserialize))]
pub struct Configuration {
    /// Domain associated with the creator.
    pub domain: String,
    /// The private key in PKCS#8 or SEC1 PEM form used to sign OWIDs.
    pub private_key: String,
    /// The public key in SPKI PEM form. Optional because it can be derived
    /// from the private key.
    pub public_key: Option<String>,
}

/// Needed to create new OWIDs.
///
/// A creator binds the domain that hosts the well known end points to the
/// crypto instance holding the signing key.
#[derive(Debug, Clone)]
pub struct Creator {
    domain: String,
    crypto: Crypto,
}

impl Creator {
    /// Creates a new creator for the domain using the crypto instance for
    /// signing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] if the domain is empty or
    /// whitespace, [`Error::DomainTooLong`] if the domain is longer than
    /// the maximum a domain name may be, or [`Error::KeyMissing`] if the
    /// crypto instance can not sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let owid = creator.create("Hello World").unwrap();
    /// assert_eq!("example.com", owid.domain());
    /// ```
    pub fn new(domain: &str, crypto: Crypto) -> Result<Self> {
        if domain.trim().is_empty() {
            return Err(Error::InvalidDomain(domain.to_owned()));
        }
        // Refused here, where the caller supplies the domain, so a creator
        // that could only produce OWIDs this crate refuses to read never
        // exists, and nothing is signed before the caller is told. The
        // count is of bytes because the domain field carries the bytes and
        // the read measures them.
        if domain.len() > MAXIMUM_DOMAIN_LENGTH {
            return Err(Error::DomainTooLong);
        }
        if !crypto.can_sign() {
            return Err(Error::KeyMissing("generate a signature"));
        }
        Ok(Creator {
            domain: domain.to_owned(),
            crypto,
        })
    }

    /// Creates a new creator from configuration containing the domain and
    /// the private key PEM.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidDomain`] if the domain is empty or
    /// whitespace, [`Error::DomainTooLong`] if the domain is longer than
    /// the maximum a domain name may be, or [`Error::Key`] if the private
    /// key PEM is not valid.
    pub fn from_configuration(configuration: &Configuration) -> Result<Self> {
        let crypto = Crypto::new_sign_only(&configuration.private_key)?;
        Creator::new(&configuration.domain, crypto)
    }

    /// Domain associated with the OWID creator. Contains well known end
    /// points to provide public keys and other information needed to
    /// conform to the OWID specification.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Used to sign OWIDs from this creator.
    pub fn crypto(&self) -> &Crypto {
        &self.crypto
    }

    /// Creates and signs an OWID carrying the payload given, which may be
    /// anything that becomes bytes, such as a string or a byte vector.
    ///
    /// This is the only way to make an OWID, the other route to one being a
    /// successful read. The creator owns the version, the domain, the date
    /// and the signature, and a caller supplies the payload, so there is no
    /// moment at which a partly built OWID exists for anyone to hold or
    /// pass on.
    ///
    /// # Errors
    ///
    /// Returns errors if the fields can not be encoded or the signing
    /// operation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    ///
    /// let from_text = creator.create("Hello World").unwrap();
    /// let from_bytes = creator.create(vec![0x01, 0x03]).unwrap();
    ///
    /// assert_eq!(from_text.payload_as_string(), "Hello World");
    /// assert_eq!(from_bytes.payload(), [0x01, 0x03]);
    /// assert_eq!(from_text.signature().len(), owid::SIGNATURE_LENGTH);
    /// ```
    ///
    /// There is no public way to sign an OWID that already exists, because
    /// re-signing one would replace a signature its fields were read with.
    ///
    /// ```compile_fail
    /// use owid::{Creator, Crypto};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let mut owid = creator.create("Hello World").unwrap();
    ///
    /// creator.sign(&mut owid).unwrap();
    /// ```
    pub fn create(&self, payload: impl Into<Vec<u8>>) -> Result<Owid> {
        self.create_with_others(payload, &[])
    }

    /// Creates and signs an OWID whose signature covers the other OWIDs as
    /// well, as a processor does when adding itself to a transaction. The
    /// same others, in the same order, must be passed when verifying.
    ///
    /// # Errors
    ///
    /// See [`Creator::create`].
    pub fn create_with_others(
        &self,
        payload: impl Into<Vec<u8>>,
        others: &[&Owid],
    ) -> Result<Owid> {
        self.create_version(Version::default(), payload.into(), others)
    }

    /// Creates and signs an OWID of the version given.
    ///
    /// Crate private because versions 1 and 2 are deprecated and readable
    /// for existing data only, so nothing outside should be making one. The
    /// public creation methods arrive here with the current version.
    pub(crate) fn create_version(
        &self,
        version: Version,
        payload: Vec<u8>,
        others: &[&Owid],
    ) -> Result<Owid> {
        let mut owid = Owid::from_parts(
            version,
            self.domain.clone(),
            Utc::now(),
            payload,
            Vec::new(),
        );
        let data = owid.data_for_crypto(others)?;
        let signature = self.crypto.sign_byte_array(&data)?;
        if signature.len() != crate::SIGNATURE_LENGTH {
            return Err(Error::InvalidSignatureLength(signature.len()));
        }
        owid.set_signature(signature);
        Ok(owid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A domain of the length given, built from labels of the 63
    /// characters RFC 1035 section 2.3.4 allows, separated by dots, so the
    /// value is a domain in shape as well as in length.
    fn domain_of_length(length: usize) -> String {
        let mut value = String::new();
        while value.len() < length {
            if !value.is_empty() {
                value.push('.');
            }
            let label = (length - value.len()).min(63);
            for _ in 0..label {
                value.push('a');
            }
        }
        assert_eq!(value.len(), length, "should build the length asked for");
        value
    }

    /// The longest domain allowed is accepted, signs, and the OWID it
    /// produces reads back with the same domain. These tests read the
    /// maximum from the constant rather than spelling the number out,
    /// because what they check is that the write stops exactly where the
    /// read does. The number itself is pinned by the tests in
    /// `tests/payload_length.rs`, which can not see a crate private
    /// constant.
    #[test]
    fn domain_of_maximum_length_is_accepted() {
        let domain = domain_of_length(MAXIMUM_DOMAIN_LENGTH);
        let creator = Creator::new(&domain, Crypto::new()).expect("should create the creator");
        let owid = creator.create("Hello World").expect("should create");
        let bytes = owid.as_byte_array().expect("should serialize");
        let parsed = Owid::from_byte_array(&bytes).expect("should parse back");
        assert_eq!(parsed.domain(), domain, "domain should round trip");
        assert_eq!(
            parsed.payload(),
            owid.payload(),
            "payload should round trip"
        );
    }

    /// The deprecated versions can still be written and read, which the
    /// crate needs for data created by earlier implementations. Creating
    /// one is crate private, so this test lives here rather than with the
    /// tests outside the crate, and it is the round trip that matters
    /// rather than the way the OWID was made.
    #[test]
    fn deprecated_versions_round_trip() {
        let crypto = Crypto::new();
        let creator = Creator::new("test.com", crypto.clone()).expect("should create the creator");
        for version in [Version::Version1, Version::Version2] {
            let owid = creator
                .create_version(version, b"Hello World".to_vec(), &[])
                .expect("should create");
            let encoded = owid.as_base64().expect("should encode");
            let copy = Owid::from_base64(&encoded).expect("should decode");
            assert_eq!(copy.version(), version, "version should round trip");
            assert_eq!(copy.domain(), owid.domain(), "domain should round trip");
            assert_eq!(copy.payload(), owid.payload(), "payload should round trip");
            assert_eq!(
                copy.signature(),
                owid.signature(),
                "signature should round trip"
            );
            assert!(
                copy.verify_with_crypto(&crypto, &[])
                    .expect("should verify"),
                "a deprecated version should still verify"
            );
        }
    }

    /// One character more than the maximum is refused where the domain is
    /// supplied, so the creator never exists and nothing it would have
    /// signed is produced.
    #[test]
    fn domain_over_maximum_is_refused() {
        let domain = domain_of_length(MAXIMUM_DOMAIN_LENGTH + 1);
        let error = Creator::new(&domain, Crypto::new()).expect_err("should refuse");
        assert!(
            matches!(error, Error::DomainTooLong),
            "a domain one character over the maximum should be refused, got {error:?}"
        );
        let expected =
            format!("domain field exceeds the '{MAXIMUM_DOMAIN_LENGTH}' character maximum");
        assert_eq!(
            error.to_string(),
            expected,
            "message should name the maximum"
        );
    }

    /// The domain is refused before the crypto instance is looked at, so a
    /// creator given both a long domain and a key that can not sign
    /// reports the domain. Signing is the only work this type does, and
    /// the refusal arrives before the key that would do it is examined, so
    /// no signature can have been computed over a domain that will be
    /// refused.
    #[test]
    fn domain_is_refused_before_the_key_is_examined() {
        let public_pem = Crypto::new()
            .public_key_pem()
            .expect("should export the public key");
        let verify_only = Crypto::new_verify_only(&public_pem).expect("should import the key");
        assert!(!verify_only.can_sign(), "should not be able to sign");
        let domain = domain_of_length(MAXIMUM_DOMAIN_LENGTH + 1);
        let error = Creator::new(&domain, verify_only).expect_err("should refuse");
        assert!(
            matches!(error, Error::DomainTooLong),
            "the domain should be refused before the key, got {error:?}"
        );
    }

    /// A configuration carrying a long domain is refused as well, so the
    /// bound is not avoided by building a creator from settings.
    #[test]
    fn configuration_with_long_domain_is_refused() {
        let crypto = Crypto::new();
        let configuration = Configuration {
            domain: domain_of_length(MAXIMUM_DOMAIN_LENGTH + 1),
            private_key: crypto.private_key_pem().expect("should export the key"),
            public_key: None,
        };
        let error = Creator::from_configuration(&configuration).expect_err("should refuse");
        assert!(
            matches!(error, Error::DomainTooLong),
            "a long domain in configuration should be refused, got {error:?}"
        );
    }

    /// An empty domain is the invalid domain error it was before the
    /// length bound was added, so the bound has not taken over an
    /// unrelated case.
    #[test]
    fn empty_domain_is_still_invalid_domain() {
        let error = Creator::new("   ", Crypto::new()).expect_err("should refuse");
        assert!(
            matches!(&error, Error::InvalidDomain(d) if d.as_str() == "   "),
            "an empty domain should stay the invalid domain error, got {error:?}"
        );
    }
}

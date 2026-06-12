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
use crate::owid::Owid;

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
    /// whitespace, or [`Error::KeyMissing`] if the crypto instance can not
    /// sign.
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Creator, Crypto};
    ///
    /// let creator = Creator::new("example.com", Crypto::new()).unwrap();
    /// let owid = creator.sign_string("Hello World").unwrap();
    /// assert_eq!("example.com", owid.domain);
    /// ```
    pub fn new(domain: &str, crypto: Crypto) -> Result<Self> {
        if domain.trim().is_empty() {
            return Err(Error::InvalidDomain(domain.to_owned()));
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
    /// whitespace, or [`Error::Key`] if the private key PEM is not valid.
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

    /// Signs the OWID provided, setting the domain to the creator domain and
    /// the date to the current time.
    ///
    /// # Errors
    ///
    /// Returns errors if the fields can not be encoded or the signing
    /// operation fails.
    pub fn sign(&self, owid: &mut Owid) -> Result<()> {
        self.sign_with_others(owid, &[])
    }

    /// Signs the OWID provided together with the other OWIDs provided. The
    /// same others, in the same order, must be passed when verifying.
    ///
    /// # Errors
    ///
    /// Returns errors if the fields can not be encoded or the signing
    /// operation fails.
    pub fn sign_with_others(&self, owid: &mut Owid, others: &[&Owid]) -> Result<()> {
        owid.domain = self.domain.clone();
        owid.date = Utc::now();
        let data = owid.data_for_crypto(others)?;
        owid.signature = self.crypto.sign_byte_array(&data)?;
        if owid.signature.len() != crate::SIGNATURE_LENGTH {
            return Err(Error::InvalidSignatureLength(owid.signature.len()));
        }
        Ok(())
    }

    /// Creates a new signed OWID for the creator containing the string as
    /// the payload.
    ///
    /// # Errors
    ///
    /// See [`Creator::sign`].
    pub fn sign_string(&self, value: &str) -> Result<Owid> {
        self.sign_bytes(value.as_bytes().to_vec())
    }

    /// Creates a new signed OWID for the creator containing the bytes as the
    /// payload.
    ///
    /// # Errors
    ///
    /// See [`Creator::sign`].
    pub fn sign_bytes(&self, value: Vec<u8>) -> Result<Owid> {
        let mut owid = Owid {
            payload: value,
            ..Owid::default()
        };
        self.sign(&mut owid)?;
        Ok(owid)
    }
}

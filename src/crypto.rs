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

//! All the public and support methods associated with signing and
//! verification. Nothing to do with the web or HTTP.
//!
//! OWID uses ECDSA with the NIST P-256 curve (also known as secp256r1 or
//! prime256v1) and the SHA-256 hash, as required by the specification. The
//! signature is the 64 byte concatenation of the big endian r and s values.

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _, LineEnding};
use p256::SecretKey;
use rand_core::OsRng;

use crate::error::{Error, Result};
use crate::SIGNATURE_LENGTH;

/// Holds the public and private keys used to sign and verify OWIDs.
///
/// An instance can hold both keys, or only one of them when created with
/// [`Crypto::new_sign_only`] or [`Crypto::new_verify_only`].
#[derive(Debug, Clone)]
pub struct Crypto {
    signing_key: Option<SigningKey>,
    verifying_key: Option<VerifyingKey>,
}

impl Crypto {
    /// Creates a new instance and generates a public and private key pair
    /// used to sign and verify OWIDs.
    pub fn new() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();
        Crypto {
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        }
    }

    /// Creates a new instance for signing OWIDs from the private key PEM
    /// provided. Both PKCS#8 ("PRIVATE KEY") and SEC1 ("EC PRIVATE KEY")
    /// PEM forms are accepted, matching the forms produced by the other
    /// language implementations.
    ///
    /// The verifying key is derived from the private key so the instance can
    /// also verify.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Key`] if the PEM is not a valid P-256 private key.
    pub fn new_sign_only(private_pem: &str) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(private_pem)
            .or_else(|_| SecretKey::from_sec1_pem(private_pem).map(SigningKey::from))
            .map_err(|e| Error::Key(e.to_string()))?;
        let verifying_key = *signing_key.verifying_key();
        Ok(Crypto {
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        })
    }

    /// Creates a new instance for verifying OWIDs from the public key PEM
    /// provided in Subject Public Key Info (SPKI) form.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Key`] if the PEM is not a valid P-256 public key.
    pub fn new_verify_only(public_pem: &str) -> Result<Self> {
        let verifying_key =
            VerifyingKey::from_public_key_pem(public_pem).map_err(|e| Error::Key(e.to_string()))?;
        Ok(Crypto {
            signing_key: None,
            verifying_key: Some(verifying_key),
        })
    }

    /// Signs the byte array with the private key and returns the 64 byte
    /// signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyMissing`] if the instance was created for
    /// verification only.
    pub fn sign_byte_array(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(Error::KeyMissing("generate a signature"))?;
        let signature: Signature = signing_key.sign(data);
        let bytes = signature.to_bytes().to_vec();
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(Error::InvalidSignatureLength(bytes.len()));
        }
        Ok(bytes)
    }

    /// Returns true if the signature is valid for the data.
    ///
    /// A signature of the wrong length returns
    /// [`Error::InvalidSignatureLength`]. A signature of the right length
    /// that does not match the data returns false rather than an error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyMissing`] if the instance was created for signing
    /// only without a derivable public key.
    pub fn verify_byte_array(&self, data: &[u8], signature: &[u8]) -> Result<bool> {
        let verifying_key = self
            .verifying_key
            .as_ref()
            .ok_or(Error::KeyMissing("verify a signature"))?;
        if signature.len() != SIGNATURE_LENGTH {
            return Err(Error::InvalidSignatureLength(signature.len()));
        }
        match Signature::from_slice(signature) {
            Ok(signature) => Ok(verifying_key.verify(data, &signature).is_ok()),
            // Bytes that can not form a valid signature, for example r or s
            // values of zero, can never verify.
            Err(_) => Ok(false),
        }
    }

    /// Returns the public key in Subject Public Key Info (SPKI) PEM form for
    /// use with the well known end points or other implementations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyMissing`] if the instance has no public key, or
    /// [`Error::Key`] if the export fails.
    pub fn subject_public_key_info(&self) -> Result<String> {
        let verifying_key = self
            .verifying_key
            .as_ref()
            .ok_or(Error::KeyMissing("export a public key"))?;
        verifying_key
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| Error::Key(e.to_string()))
    }

    /// Returns the public key in PEM form. Alias of
    /// [`Crypto::subject_public_key_info`].
    ///
    /// # Errors
    ///
    /// See [`Crypto::subject_public_key_info`].
    pub fn public_key_pem(&self) -> Result<String> {
        self.subject_public_key_info()
    }

    /// Returns the private key in PKCS#8 PEM form.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyMissing`] if the instance has no private key, or
    /// [`Error::Key`] if the export fails.
    pub fn private_key_pem(&self) -> Result<String> {
        let signing_key = self
            .signing_key
            .as_ref()
            .ok_or(Error::KeyMissing("export a private key"))?;
        signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|e| Error::Key(e.to_string()))
    }

    /// Returns the verifying key if the instance has one.
    pub fn verifying_key(&self) -> Option<&VerifyingKey> {
        self.verifying_key.as_ref()
    }

    /// True if the instance can be used to sign OWIDs.
    pub fn can_sign(&self) -> bool {
        self.signing_key.is_some()
    }

    /// True if the instance can be used to verify OWIDs.
    pub fn can_verify(&self) -> bool {
        self.verifying_key.is_some()
    }
}

impl Default for Crypto {
    fn default() -> Self {
        Crypto::new()
    }
}

impl From<SigningKey> for Crypto {
    fn from(signing_key: SigningKey) -> Self {
        let verifying_key = *signing_key.verifying_key();
        Crypto {
            signing_key: Some(signing_key),
            verifying_key: Some(verifying_key),
        }
    }
}

impl From<VerifyingKey> for Crypto {
    fn from(verifying_key: VerifyingKey) -> Self {
        Crypto {
            signing_key: None,
            verifying_key: Some(verifying_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PAYLOAD: &[u8] = b"test";

    /// Port of the Go TestInvalidPublicPem test.
    #[test]
    fn invalid_public_pem() {
        let result = Crypto::new_verify_only("invalid");
        assert!(result.is_err(), "bad public PEM should error");
    }

    /// Port of the Go TestInvalidPrivatePem test.
    #[test]
    fn invalid_private_pem() {
        let result = Crypto::new_sign_only("invalid");
        assert!(result.is_err(), "bad private PEM should error");
    }

    /// Port of the Go TestCrypto test. Keys exported to PEM and imported
    /// into sign only and verify only instances must produce signatures
    /// that verify.
    #[test]
    fn sign_and_verify_via_pem() {
        let crypto = Crypto::new();
        let private_pem = crypto
            .private_key_pem()
            .expect("should export the private key");
        let public_pem = crypto
            .public_key_pem()
            .expect("should export the public key");
        let signer = Crypto::new_sign_only(&private_pem).expect("should import the private key");
        let verifier = Crypto::new_verify_only(&public_pem).expect("should import the public key");
        let signature = signer
            .sign_byte_array(TEST_PAYLOAD)
            .expect("should sign the payload");
        let valid = verifier
            .verify_byte_array(TEST_PAYLOAD, &signature)
            .expect("should verify the payload");
        assert!(valid, "signature should be valid");
    }

    /// A verify only instance can not sign.
    #[test]
    fn verify_only_cannot_sign() {
        let crypto = Crypto::new();
        let public_pem = crypto
            .public_key_pem()
            .expect("should export the public key");
        let verifier = Crypto::new_verify_only(&public_pem).expect("should import the public key");
        let result = verifier.sign_byte_array(TEST_PAYLOAD);
        assert!(
            matches!(result, Err(Error::KeyMissing(_))),
            "verify only instance should not sign"
        );
    }

    /// Signatures of the wrong length are rejected with an error.
    #[test]
    fn wrong_length_signature_errors() {
        let crypto = Crypto::new();
        let result = crypto.verify_byte_array(TEST_PAYLOAD, &[0u8; 63]);
        assert!(
            matches!(result, Err(Error::InvalidSignatureLength(63))),
            "should reject a 63 byte signature"
        );
    }
}

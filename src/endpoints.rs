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

//! Helpers for hosting the well known end points required by the OWID
//! specification. These are framework agnostic. They return the path and
//! body so that any HTTP server, including WebAssembly edge runtimes, can
//! serve them.
//!
//! The mandatory end points are:
//!
//! - `/owid/api/v{version}/creator` returning JSON with the domain, common
//!   name, and public key of the creator.
//! - `/owid/api/v{version}/public-key` returning the public key as PEM text.
//!   The `format` query parameter must be `spki` or `pkcs`.

use serde::{Deserialize, Serialize};

use crate::creator::Creator;
use crate::error::{Error, Result};
use crate::version::Version;

/// Used by a supply chain partner to cache the public key associated with
/// the domain so that they do not need to call the end points to verify a
/// signature. For example, a request is received with OWIDs and those OWIDs
/// need to be verified before the bid is processed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicCreator {
    /// The domain that the name and key relate to.
    #[serde(rename = "domain")]
    pub domain: String,
    /// Common name of the creator.
    #[serde(rename = "name")]
    pub name: String,
    /// The public key in SPKI form.
    #[serde(rename = "publicKeySPKI")]
    pub public_key_spki: String,
    /// URL with the terms associated with the creation of the data in the
    /// OWID.
    #[serde(rename = "contractURL", default)]
    pub contract_url: String,
}

/// Returns the path of the creator end point for the version provided. For
/// example `/owid/api/v3/creator`.
pub fn creator_path(version: Version) -> String {
    format!("/owid/api/v{}/creator", version.as_byte())
}

/// Returns the path of the public key end point for the version provided.
/// For example `/owid/api/v3/public-key`.
pub fn public_key_path(version: Version) -> String {
    format!("/owid/api/v{}/public-key", version.as_byte())
}

/// Returns the JSON body for the creator end point.
///
/// # Errors
///
/// Returns [`Error::Key`] if the public key can not be exported or the JSON
/// can not be produced.
pub fn creator_response(creator: &Creator, name: &str, contract_url: &str) -> Result<String> {
    let public = PublicCreator {
        domain: creator.domain().to_owned(),
        name: name.to_owned(),
        public_key_spki: creator.crypto().subject_public_key_info()?,
        contract_url: contract_url.to_owned(),
    };
    serde_json::to_string(&public).map_err(|e| Error::Key(e.to_string()))
}

/// Returns the text body for the public key end point.
///
/// The specification allows the key to be requested in SPKI or PKCS form.
/// This implementation returns the SPKI PEM for both values because the
/// importers in every implementation accept it.
///
/// # Errors
///
/// Returns [`Error::InvalidKeyFormat`] if the format is not `spki` or
/// `pkcs`, or [`Error::Key`] if the public key can not be exported.
pub fn public_key_response(creator: &Creator, format: &str) -> Result<String> {
    match format {
        "spki" | "pkcs" => creator.crypto().subject_public_key_info(),
        other => Err(Error::InvalidKeyFormat(other.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    fn new_creator() -> Creator {
        Creator::new("example.com", Crypto::new()).expect("should create the creator")
    }

    /// The creator end point body must contain the JSON fields named in the
    /// specification.
    #[test]
    fn creator_response_fields() {
        let creator = new_creator();
        let body =
            creator_response(&creator, "Example Org", "").expect("should produce the creator JSON");
        let parsed: PublicCreator = serde_json::from_str(&body).expect("should parse the JSON");
        assert_eq!(parsed.domain, "example.com", "should contain the domain");
        assert_eq!(parsed.name, "Example Org", "should contain the name");
        assert!(
            parsed.public_key_spki.contains("BEGIN PUBLIC KEY"),
            "should contain the public key PEM"
        );
        assert!(
            body.contains("publicKeySPKI"),
            "should use the JSON field names from the specification"
        );
    }

    /// The public key end point requires a valid format parameter.
    #[test]
    fn public_key_response_formats() {
        let creator = new_creator();
        for format in ["spki", "pkcs"] {
            let body = public_key_response(&creator, format).expect("should return the public key");
            assert!(
                body.contains("BEGIN PUBLIC KEY"),
                "should return the PEM for format {format}"
            );
        }
        let result = public_key_response(&creator, "other");
        assert!(
            matches!(result, Err(Error::InvalidKeyFormat(_))),
            "should reject unknown formats"
        );
    }

    /// The paths must match the well known end points in the specification.
    #[test]
    fn paths() {
        assert_eq!(creator_path(Version::Version3), "/owid/api/v3/creator");
        assert_eq!(
            public_key_path(Version::Version3),
            "/owid/api/v3/public-key"
        );
    }
}

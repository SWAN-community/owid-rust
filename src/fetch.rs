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

//! Verification that fetches the creator public key over HTTP from the well
//! known end point associated with the OWID domain. Available with the
//! `fetch` feature.
//!
//! Keys are cached in memory after the first request, as recommended by the
//! specification, to avoid repeated requests to the public-key end point of
//! other processors.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::error::{Error, Result};
use crate::owid::Owid;

/// Cache used to avoid repeat requests for the same public keys.
fn cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns the URL of the public key end point for the OWID using the scheme
/// provided, normally `https`.
pub fn public_key_url(owid: &Owid, scheme: &str) -> String {
    format!(
        "{}://{}/owid/api/v{}/public-key?format=pkcs",
        scheme,
        owid.domain,
        owid.version.as_byte()
    )
}

/// Fetches the public key PEM for the URL, using the cache when possible.
fn public_key_pem(url: &str) -> Result<String> {
    if let Some(pem) = cache()
        .lock()
        .expect("should lock the public key cache")
        .get(url)
    {
        return Ok(pem.clone());
    }
    let pem = ureq::get(url)
        .call()
        .map_err(|e| Error::Http(e.to_string()))?
        .into_string()
        .map_err(|e| Error::Http(e.to_string()))?;
    cache()
        .lock()
        .expect("should lock the public key cache")
        .insert(url.to_owned(), pem.clone());
    Ok(pem)
}

impl Owid {
    /// Verifies this OWID, and any others that were included when it was
    /// signed, by fetching the public key from the domain associated with
    /// the OWID. The scheme is normally `https`.
    ///
    /// Pass an empty slice for `others` when the OWID was signed on its own.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the public key can not be fetched, or any
    /// error from [`Owid::verify_with_public_key`].
    pub fn verify(&self, scheme: &str, others: &[&Owid]) -> Result<bool> {
        let pem = public_key_pem(&public_key_url(self, scheme))?;
        self.verify_with_public_key(&pem, others)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    /// The URL must match the well known end point in the specification.
    #[test]
    fn url_format() {
        let owid = Owid::new("example.com", Utc::now(), Vec::new());
        assert_eq!(
            public_key_url(&owid, "https"),
            "https://example.com/owid/api/v3/public-key?format=pkcs",
            "should build the well known end point URL"
        );
    }
}

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

//! The built in transport for [`Owid::verify`](crate::Owid::verify), over
//! asynchronous reqwest with rustls. Available with the `reqwest-fetch`
//! feature, which is for hosts that have no HTTP of their own. On a
//! WebAssembly target the host provides HTTP and a
//! [`PublicKeyFetch`] written over it is used instead.

use std::time::Duration;

use reqwest::redirect::Policy;

use crate::error::{Error, Result};
use crate::fetch::{FetchResponse, LocalBoxFuture, PublicKeyFetch};

/// How long a key fetch may take before it is reported as a key that could
/// not be obtained rather than left hanging.
const KEY_FETCH_TIMEOUT_SECONDS: u64 = 10;

/// A [`PublicKeyFetch`] over reqwest.
///
/// The client never follows a redirect, so a creator whose domain answers
/// 3xx has its key reported as unavailable without the request to the other
/// host ever being made, and it waits at most ten seconds for an answer.
/// There is no way to supply a client of the caller's own, because a client
/// built elsewhere could follow redirects, and the point of this type is
/// that it cannot.
///
/// The client holds a connection pool, so build one and share it rather
/// than building one per verification.
#[derive(Debug, Clone)]
pub struct ReqwestFetch {
    client: reqwest::Client,
}

impl ReqwestFetch {
    /// Builds the transport.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] when the client can not be built, which
    /// reqwest reports when the TLS backend can not be set up.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .timeout(Duration::from_secs(KEY_FETCH_TIMEOUT_SECONDS))
            .build()
            .map_err(|e| Error::Http(e.to_string()))?;
        Ok(ReqwestFetch { client })
    }
}

impl PublicKeyFetch for ReqwestFetch {
    fn fetch<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<FetchResponse>> {
        Box::pin(async move {
            let response = self
                .client
                .get(url)
                .send()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;
            let status = response.status().as_u16();
            let body = response
                .text()
                .await
                .map_err(|e| Error::Http(e.to_string()))?;
            Ok(FetchResponse { status, body })
        })
    }
}

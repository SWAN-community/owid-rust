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
use crate::io::minutes_since_base;
use crate::owid::Owid;
use crate::status::SignatureStatus;

/// Cache used to avoid repeat requests for the same public keys.
fn cache() -> &'static Mutex<HashMap<String, String>> {
    static CACHE: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Returns the URL of the public key end point for the OWID using the scheme
/// provided, normally `https`.
///
/// The OWID's own date is sent as the `date` parameter, counted in whole
/// minutes from 2020-01-01, so that a creator which rotates its key returns
/// the key that was in force when this OWID was signed. Creators rotate
/// weekly, so without the date only identifiers created since the most
/// recent rotation can be verified, and every older one is reported as not
/// matching. A creator that does not support the dated lookup ignores the
/// parameter and returns its current key, which is what an undated request
/// would have received anyway.
///
/// The date is left out where it cannot be counted, which no OWID read by
/// this crate can be. See [`crate::io::minutes_since_base`].
pub fn public_key_url(owid: &Owid, scheme: &str) -> String {
    let path = format!(
        "{}://{}/owid/api/v{}/public-key",
        scheme,
        owid.domain(),
        owid.version().as_byte()
    );
    match minutes_since_base(&owid.date()) {
        Some(minutes) => format!("{path}?date={minutes}&format=pkcs"),
        None => format!("{path}?format=pkcs"),
    }
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
        self.verify_at_url(&public_key_url(self, scheme), others)
    }

    /// The work [`Owid::verify`] does once the URL is known, kept apart so
    /// that the tests drive the same fetch and check against a key end
    /// point they can stand up locally, rather than a near copy of it.
    pub(crate) fn verify_at_url(&self, url: &str, others: &[&Owid]) -> Result<bool> {
        let pem = public_key_pem(url)?;
        self.verify_with_public_key(&pem, others)
    }

    /// The same check as [`Owid::verify`], answered with the status that
    /// names the outcome.
    ///
    /// A key that can not be fetched is
    /// [`SignatureStatus::KeyUnavailable`] and one that arrives in a form
    /// this crate can not read is [`SignatureStatus::InvalidKey`]. Neither
    /// is [`SignatureStatus::Invalid`], because an outage or a badly served
    /// key leaves the signature unjudged and reporting it as invalid would
    /// read as an attack.
    pub fn verify_status(&self, scheme: &str, others: &[&Owid]) -> SignatureStatus {
        SignatureStatus::of(self.verify(scheme, others))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator::Creator;
    use crate::crypto::Crypto;
    use crate::io::{base_date, minutes_since_base};
    use chrono::{DateTime, Duration, Utc};
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// A genuine 51Did creator context identifier, created on 2026-09-04 by
    /// cloud.51degrees.com for the creator domain 51d.es. It is public and
    /// carries no secret.
    const IDENTIFIER_FIXTURE: &str = include_str!("../tests/data/identifier.txt");

    /// The published 51d.es public key schedule, being thirty weekly keys
    /// from 11 May to 30 November 2026, as the public key end point serves
    /// them.
    const SCHEDULE_FIXTURE: &str = include_str!("../tests/data/public-key-schedule.txt");

    /// The minute count the fixture identifier was created at, which is
    /// 2026-09-04T00:00:00Z counted from 2020-01-01. Written out rather than
    /// computed, so that a change to the counting is caught here instead of
    /// being carried into the expected URL as well.
    const IDENTIFIER_MINUTES: u32 = 3_510_720;

    /// One entry of the published schedule, being the date the key came into
    /// force and the PEM the end point serves it as.
    struct ScheduledKey {
        starts_at: DateTime<Utc>,
        pem: String,
    }

    /// Reads a fixture file, dropping the comment lines that describe it and
    /// any blank lines, and returning the records that remain.
    fn records(fixture: &str) -> Vec<&str> {
        fixture
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect()
    }

    /// The genuine identifier from the fixture.
    fn identifier() -> Owid {
        let value = records(IDENTIFIER_FIXTURE);
        assert_eq!(value.len(), 1, "the fixture holds one identifier");
        Owid::from_base64(value[0]).expect("should read the genuine identifier")
    }

    /// The published schedule from the fixture, oldest key first. The fixture
    /// stores the base 64 body of each key, which is wrapped back into the
    /// PEM the end point serves.
    fn schedule() -> Vec<ScheduledKey> {
        records(SCHEDULE_FIXTURE)
            .iter()
            .map(|record| {
                let (date, body) = record
                    .split_once(' ')
                    .expect("a record is a date and a key");
                let wrapped = body
                    .as_bytes()
                    .chunks(64)
                    .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
                    .collect::<Vec<_>>()
                    .join("\n");
                ScheduledKey {
                    starts_at: DateTime::parse_from_rfc3339(date)
                        .expect("should read the date the key came into force")
                        .with_timezone(&Utc),
                    pem: format!(
                        "-----BEGIN PUBLIC KEY-----\n{wrapped}\n-----END PUBLIC KEY-----\n"
                    ),
                }
            })
            .collect()
    }

    /// The key that was in force at the date given, which is the newest one
    /// that had already started, or `None` where the schedule starts after
    /// the date.
    fn key_in_force(schedule: &[ScheduledKey], date: DateTime<Utc>) -> Option<&ScheduledKey> {
        schedule.iter().rev().find(|key| key.starts_at <= date)
    }

    /// A stand in for the creator public key end point, answering the way the
    /// cloud controller does. A request naming a date is served the key that
    /// was in force then, a request without one is served the newest key in
    /// the schedule, which is what the current key means, and a date the
    /// schedule does not reach is a 404.
    ///
    /// It records the date parameter of every request, so a test can say what
    /// went over the wire rather than only what the URL builder returned.
    struct KeyServer {
        base: String,
        dates: Arc<Mutex<Vec<Option<String>>>>,
    }

    impl KeyServer {
        fn start() -> KeyServer {
            let listener = TcpListener::bind("127.0.0.1:0").expect("should bind the end point");
            let base = format!(
                "http://{}",
                listener.local_addr().expect("should have an address")
            );
            let dates = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&dates);
            // The thread ends when the test binary does. Nothing outlives the
            // process, and stopping the listener would mean synchronising
            // with a thread blocked in accept for no gain.
            thread::spawn(move || {
                let schedule = schedule();
                for stream in listener.incoming() {
                    let mut stream = match stream {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    let mut reader =
                        BufReader::new(stream.try_clone().expect("should clone the connection"));
                    let mut request = String::new();
                    reader
                        .read_line(&mut request)
                        .expect("should read the request line");
                    // The headers are not used, and are read so the client is
                    // not left writing into a connection nobody is draining.
                    loop {
                        let mut header = String::new();
                        let read = reader
                            .read_line(&mut header)
                            .expect("should read a header line");
                        if read == 0 || header.trim().is_empty() {
                            break;
                        }
                    }
                    let target = request.split_whitespace().nth(1).unwrap_or("").to_owned();
                    let date = query_value(&target, "date");
                    seen.lock()
                        .expect("should lock the record of requests")
                        .push(date.clone());
                    let key = match date {
                        None => schedule.last(),
                        Some(minutes) => {
                            let minutes: i64 =
                                minutes.parse().expect("the date should be a number");
                            key_in_force(&schedule, base_date() + Duration::minutes(minutes))
                        }
                    };
                    let response = match key {
                        Some(key) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: \
                             {}\r\nConnection: close\r\n\r\n{}",
                            key.pem.len(),
                            key.pem
                        ),
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: \
                                 close\r\n\r\n"
                            .to_owned(),
                    };
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });
            KeyServer { base, dates }
        }

        /// The date parameter of every request served so far, in order.
        fn dates(&self) -> Vec<Option<String>> {
            self.dates
                .lock()
                .expect("should lock the record of requests")
                .clone()
        }

        /// The URL a fetch would use, with the creator host replaced by this
        /// server. The path and query are the ones the crate builds, so what
        /// is under test is the real URL rather than a copy of it.
        fn url_for(&self, owid: &Owid) -> String {
            let built = public_key_url(owid, "http");
            let path = built
                .split_once(owid.domain())
                .expect("the URL carries the creator domain")
                .1;
            format!("{}{}", self.base, path)
        }
    }

    /// The value of a query parameter in a request target, or `None` where
    /// the target does not carry it.
    fn query_value(target: &str, name: &str) -> Option<String> {
        target
            .split_once('?')?
            .1
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .map(str::to_owned)
    }

    /// The URL must match the well known end point in the specification, and
    /// must name the minute the OWID was created so that the creator can
    /// return the key that was in force then.
    #[test]
    fn url_format() {
        let creator = Creator::new("example.com", Crypto::new()).expect("should create");
        let owid = creator.create(Vec::new()).expect("should create");
        let minutes = minutes_since_base(&owid.date()).expect("should count the minutes");
        assert_eq!(
            public_key_url(&owid, "https"),
            format!("https://example.com/owid/api/v3/public-key?date={minutes}&format=pkcs"),
            "should build the well known end point URL with the date"
        );
    }

    /// The genuine identifier names the minute it was created, which is the
    /// value the end point selects a key by.
    #[test]
    fn url_names_the_minute_the_identifier_was_created() {
        assert_eq!(
            public_key_url(&identifier(), "https"),
            format!("https://51d.es/owid/api/v3/public-key?date={IDENTIFIER_MINUTES}&format=pkcs"),
            "should ask 51d.es for the key in force on 2026-09-04"
        );
    }

    /// The genuine identifier verifies against the key the published schedule
    /// says was in force on the day it was created. This is the fixed point
    /// the rest of these tests are measured against, because it uses no HTTP
    /// and no URL building at all.
    #[test]
    fn genuine_identifier_verifies_against_the_key_in_force_on_its_date() {
        let owid = identifier();
        let schedule = schedule();
        let key = key_in_force(&schedule, owid.date()).expect("the schedule covers the date");
        assert_eq!(
            key.starts_at.to_rfc3339(),
            "2026-08-31T00:00:00+00:00",
            "the week beginning 31 August covers 4 September"
        );
        assert_eq!(
            owid.verify_status_with_public_key(&key.pem, &[]),
            SignatureStatus::Valid,
            "should verify against the key that signed it"
        );
    }

    /// The newest key in the schedule does not verify it, which is the whole
    /// reason the date has to be sent. Keys rotate weekly, so the key that is
    /// current when an identifier is checked is not the key that signed it
    /// unless the check happens in the same week.
    #[test]
    fn the_current_key_does_not_verify_an_earlier_weeks_identifier() {
        let owid = identifier();
        let schedule = schedule();
        let current = schedule.last().expect("the schedule holds keys");
        assert_eq!(
            owid.verify_status_with_public_key(&current.pem, &[]),
            SignatureStatus::Invalid,
            "a later week's key should not verify an earlier week's identifier"
        );
    }

    /// The fetch asks for the key in force when the identifier was signed and
    /// verifies it, with the identifier signed in a week earlier than the one
    /// the end point counts as current. This is the case the missing date
    /// parameter broke, and it fails without the fix.
    #[test]
    fn dated_fetch_verifies_an_identifier_from_an_earlier_key_week() {
        let owid = identifier();
        let server = KeyServer::start();
        assert!(
            owid.verify_at_url(&server.url_for(&owid), &[])
                .expect("should fetch the key and check the signature"),
            "should verify against the key in force when it was signed"
        );
        assert_eq!(
            server.dates(),
            vec![Some(IDENTIFIER_MINUTES.to_string())],
            "the request should name the minute the identifier was created"
        );
    }

    /// The same identifier against the same end point without the date, which
    /// is the request this crate made before the fix. The end point answers
    /// with its current key, the signature does not match it, and a genuine
    /// identifier reads as a forgery.
    #[test]
    fn undated_fetch_leaves_an_earlier_weeks_identifier_unverified() {
        let owid = identifier();
        let server = KeyServer::start();
        let undated = format!(
            "{}/owid/api/v{}/public-key?format=pkcs",
            server.base,
            owid.version().as_byte()
        );
        assert_eq!(
            SignatureStatus::of(owid.verify_at_url(&undated, &[])),
            SignatureStatus::Invalid,
            "an undated request gets the current key, which did not sign it"
        );
        assert_eq!(
            server.dates(),
            vec![None],
            "the request should carry no date, as it did before the fix"
        );
    }

    /// An end point that cannot serve a key for the date leaves the signature
    /// unjudged rather than reporting it as a forgery.
    #[test]
    fn a_key_the_end_point_cannot_serve_is_key_unavailable() {
        let owid = identifier();
        let server = KeyServer::start();
        // A fortnight before the schedule begins, which no key in it covers,
        // so the end point answers 404 the way the cloud does.
        let before = minutes_since_base(&(schedule()[0].starts_at - Duration::days(14)))
            .expect("should count the minutes");
        let url = format!(
            "{}/owid/api/v{}/public-key?date={}&format=pkcs",
            server.base,
            owid.version().as_byte(),
            before
        );
        assert_eq!(
            SignatureStatus::of(owid.verify_at_url(&url, &[])),
            SignatureStatus::KeyUnavailable,
            "no key means the signature was never examined"
        );
    }
}

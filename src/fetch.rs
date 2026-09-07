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
//! This crate builds the URL, decides what the answer means and holds the
//! keys it has obtained, but does not make the request itself. The request
//! is made by a [`PublicKeyFetch`] the caller supplies, so the crate can run
//! where HTTP is provided by the host, as it is on `wasm32-wasip1`, as well
//! as where it is provided by another crate. The `reqwest-fetch` feature
//! adds [`crate::ReqwestFetch`] for the second case.
//!
//! The fetch is asynchronous and its future is not required to be `Send`,
//! so no particular runtime is needed and a single threaded host can drive
//! it.
//!
//! Keys are cached in memory after the first request, as recommended by the
//! specification, to avoid repeated requests to the public-key end point of
//! other processors. Each key is held against the span of minutes the
//! creator has confirmed it for, so an identifier dated inside a confirmed
//! span is verified without a request whichever minute it carries. A caller
//! that asks for a key while another caller is already fetching it waits for
//! that fetch rather than starting a second.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use chrono::Utc;

use crate::error::{Error, Result};
use crate::io::minutes_since_base;
use crate::owid::Owid;
use crate::status::SignatureStatus;

/// The future a [`PublicKeyFetch`] answers with. It is boxed so the trait
/// can be used as a trait object, and it is not required to be `Send`, so a
/// transport tied to one thread, as a host provided one on WebAssembly is,
/// can be used without an executor that moves work between threads.
pub type LocalBoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// What a transport hands back from a public key request.
///
/// Only the status and the body are carried, because this crate decides
/// what the status means and never follows a redirect, so it has no use for
/// a location header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResponse {
    /// The HTTP status code the end point answered with.
    pub status: u16,
    /// The body of the answer as text, which is the key in PEM form when
    /// the status is 200.
    pub body: String,
}

/// The transport that makes the public key request for [`Owid::verify`].
///
/// A transport must make exactly the request it is given and hand back
/// whatever the end point answered. In particular it must never follow a
/// redirect. A creator whose domain answered 3xx to some other place would
/// otherwise have that other place's key trusted as its own, and a network
/// attacker able to bend the creator's DNS, or a creator that was simply
/// misconfigured, could put a key there and have forgeries verify. This
/// crate reads any 3xx it is handed as the key being unavailable, so a
/// transport that surfaces the redirect is safe, and only one that follows
/// it before this crate can see it would be a fault.
///
/// A transport should also give up after a reasonable time rather than
/// leave a verification hanging. The built in [`crate::ReqwestFetch`] waits
/// at most ten seconds.
///
/// The `Send + Sync` bound is on the transport, so one instance can be
/// shared between threads, and not on the future it answers with.
///
/// # Examples
///
/// A transport over whatever HTTP the host provides.
///
/// ```
/// use owid::{FetchResponse, LocalBoxFuture, PublicKeyFetch, Result};
///
/// struct HostFetch;
///
/// impl PublicKeyFetch for HostFetch {
///     fn fetch<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<FetchResponse>> {
///         Box::pin(async move {
///             // Make the request without following a redirect, and hand
///             // back the status and the body as they were answered.
///             let (status, body) = host_get(url).await?;
///             Ok(FetchResponse { status, body })
///         })
///     }
/// }
/// # async fn host_get(_url: &str) -> Result<(u16, String)> { Ok((404, String::new())) }
/// ```
pub trait PublicKeyFetch: Send + Sync {
    /// Requests the URL and answers with the status and the body.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] when no answer was obtained at all, for
    /// example because the name did not resolve, the connection failed or
    /// the transport gave up waiting.
    fn fetch<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<FetchResponse>>;
}

/// The most keys held before the cache is emptied and filled again, across
/// every creator. A bound is needed because a verifier sees identifiers from
/// many domains and many weeks, and an unbounded store would grow for as
/// long as the process runs.
const MAXIMUM_CACHED_KEYS: usize = 1024;

/// How far a creator's clock may run ahead of or behind this one's, in
/// minutes. A minute closer to now than this, or later, is asked about
/// rather than served from the cache, and is not held.
///
/// A creator reads a date later than its own now as now, and answers with
/// the key in force now. Within this window this process cannot tell whether
/// the creator read the minute as its past or as its present, so the answer
/// says nothing certain about the minute. An identifier signed just after a
/// rotation by a creator whose clock runs ahead would otherwise be served
/// the old key from a span confirmed up to now, and would read as not
/// matching until this clock caught up. Identifiers dated within the window
/// are asked about once per minute per creator, as they always were, and
/// every older identifier is served from the spans.
const CLOCK_DRIFT_ALLOWANCE_MINUTES: u32 = 15;

/// One key a creator has answered with, and the span of minutes the creator
/// has confirmed it was in force for.
///
/// A creator's key is in force from the start of its period until the next
/// key starts, so a key the creator confirms at two minutes was in force at
/// every minute between them. The span grows as the creator confirms the
/// same key for more minutes, and an identifier dated inside it is verified
/// without a request.
struct HeldKey {
    /// The key in PEM form, as the creator served it.
    pem: String,
    /// The earliest minute the creator has confirmed the key for.
    first: u32,
    /// The latest minute the creator has confirmed the key for.
    last: u32,
}

impl HeldKey {
    /// Whether the minute lies within the confirmed span.
    fn covers(&self, minute: u32) -> bool {
        self.first <= minute && minute <= self.last
    }
}

/// The keys already obtained, and the fetches under way that a later caller
/// for the same URL waits on rather than repeating.
#[derive(Default)]
struct Cache {
    /// Keys already fetched, by the creator's key end point, which is the
    /// key URL without its date. Each end point holds the keys the creator
    /// has answered with, each with the span of minutes the creator has
    /// confirmed it for.
    ///
    /// The key URL carries the date of the identifier being verified, in
    /// minutes, and a creator's key changes on the order of a week. Keyed by
    /// the whole URL, as this cache once was, two identifiers signed a minute
    /// apart never shared an entry, so a hundred identifiers over a hundred
    /// minutes made a hundred requests for one key. Keyed by end point and
    /// span, an identifier dated between two minutes the creator has already
    /// answered for is verified without a request.
    keys: HashMap<String, Vec<HeldKey>>,
    /// How many keys are held across every end point.
    held: usize,
    in_flight: HashMap<String, Arc<InFlight>>,
}

impl Cache {
    /// The key held for the end point whose confirmed span covers the
    /// minute, if any held key does.
    fn held_pem(&self, end_point: &str, minute: u32) -> Option<String> {
        self.keys
            .get(end_point)?
            .iter()
            .find(|key| key.covers(minute))
            .map(|key| key.pem.clone())
    }

    /// Records that the creator answered the minute with the key.
    ///
    /// A key already held for the end point has its span widened to take in
    /// the minute. A key not held before is added, emptying the cache first
    /// when it is full, because the domains and dates asked about come from
    /// the identifiers presented to this process and the cache must not grow
    /// on their input.
    fn hold(&mut self, end_point: &str, minute: u32, pem: &str) {
        if let Some(keys) = self.keys.get_mut(end_point) {
            let same = keys.iter().position(|key| key.pem == pem);
            if let Some(index) = same {
                if widen(keys, index, minute) {
                    return;
                }
            }
        }
        if self.held >= MAXIMUM_CACHED_KEYS {
            self.keys.clear();
            self.held = 0;
        }
        self.keys
            .entry(end_point.to_owned())
            .or_default()
            .push(HeldKey {
                pem: pem.to_owned(),
                first: minute,
                last: minute,
            });
        self.held += 1;
    }
}

/// Widens the span of the key at the index to take in the minute, and says
/// whether the minute is now within it.
///
/// The span is not widened across a minute the creator has answered with
/// another key for, because that would mean the creator had gone back to a
/// key it had left, and the minutes between the two spans are then not this
/// key's to claim. The key is held again as a separate span instead.
fn widen(keys: &mut [HeldKey], index: usize, minute: u32) -> bool {
    let key = &keys[index];
    if key.covers(minute) {
        return true;
    }
    let from = minute.min(key.first);
    let to = minute.max(key.last);
    let another_between = keys
        .iter()
        .enumerate()
        .any(|(i, other)| i != index && other.last > from && other.first < to);
    if another_between {
        return false;
    }
    let key = &mut keys[index];
    if minute < key.first {
        key.first = minute;
    } else {
        key.last = minute;
    }
    true
}

/// The key URL without its query, which names the scheme, the creator and
/// the version, and so the key end point being asked.
fn end_point_of(url: &str) -> &str {
    url.split_once('?').map_or(url, |(end_point, _)| end_point)
}

/// The minute the cache reads the URL as asking about, or `None` where the
/// cache must not be used for the request.
///
/// The date parameter where the URL carries one and it is at least
/// [`CLOCK_DRIFT_ALLOWANCE_MINUTES`] behind now. A request without a date
/// asks for the key in force now, and one dated within the allowance, or
/// later, may be read by the creator as its present rather than as the
/// minute named, so neither is served from the cache nor held in it.
fn minute_of(url: &str) -> Option<u32> {
    let oldest_recent =
        minutes_since_base(&Utc::now())?.checked_sub(CLOCK_DRIFT_ALLOWANCE_MINUTES)?;
    let minute = url
        .split_once('?')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix("date="))?
        .parse::<u32>()
        .ok()?;
    (minute <= oldest_recent).then_some(minute)
}

/// Locks the cache shared by every verification in the process. A panic
/// while the lock was held leaves the maps whole, because every change to
/// them is a single insert or removal, so a poisoned lock is used as it is.
fn cache() -> MutexGuard<'static, Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE
        .get_or_init(|| Mutex::new(Cache::default()))
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Empties the key cache, so that the next verification asks the creator
/// again for every key rather than using one already held.
///
/// The cache lives for as long as the process, so a key stays until it is
/// pushed out by the limit. A process that has learned it should no longer
/// trust a key it already holds, because the creator rotated after a
/// compromise, calls this to drop it. The same is offered by every other
/// port that caches, as `clearCache` in Java and PHP, `clear_cache` in
/// Python, `ClearKeyCache` in Go and `ClearPublicKeyCache` in .NET.
///
/// A fetch already under way is not stopped, and the callers waiting on it
/// still receive its answer. Only what is held is dropped, so a caller
/// arriving afterwards starts a fresh request.
pub fn clear_cache() {
    let mut held = cache();
    held.keys.clear();
    held.held = 0;
    held.in_flight.clear();
}

/// One fetch under way, shared between the caller making it and every
/// caller that asked for the same URL while it ran.
#[derive(Default)]
struct InFlight {
    state: Mutex<InFlightState>,
}

#[derive(Default)]
struct InFlightState {
    /// Set once the fetch has ended, whether or not it produced an outcome.
    finished: bool,
    /// The key, or the message of the failure, once the fetch has ended.
    /// Left empty when the caller making the fetch was dropped part way
    /// through, so that the callers waiting make the request themselves.
    /// A failure is carried as its message because [`Error`] is not
    /// `Clone`.
    outcome: Option<std::result::Result<String, String>>,
    /// The callers waiting for the fetch to end.
    wakers: Vec<Waker>,
}

impl InFlight {
    fn lock(&self) -> MutexGuard<'_, InFlightState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Waits for the fetch to end, answering with its outcome.
    fn finished(&self) -> Finished<'_> {
        Finished(self)
    }
}

/// A future that is ready once the fetch it waits on has ended.
struct Finished<'a>(&'a InFlight);

impl Future for Finished<'_> {
    type Output = Option<std::result::Result<String, String>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.0.lock();
        if state.finished {
            return Poll::Ready(state.outcome.clone());
        }
        // One entry per waiting caller, however many times it is polled.
        state.wakers.retain(|waker| !waker.will_wake(cx.waker()));
        state.wakers.push(cx.waker().clone());
        Poll::Pending
    }
}

/// Marks the fetch under way for a URL, and ends it when dropped, so the
/// callers waiting are woken whether the fetch finished or the caller making
/// it was dropped part way through.
struct Leader<'a> {
    url: &'a str,
    in_flight: Arc<InFlight>,
    outcome: Option<std::result::Result<String, String>>,
}

impl Drop for Leader<'_> {
    fn drop(&mut self) {
        cache().in_flight.remove(self.url);
        let wakers = {
            let mut state = self.in_flight.lock();
            state.finished = true;
            state.outcome = self.outcome.take();
            std::mem::take(&mut state.wakers)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

/// Whether a caller makes the fetch for a URL or waits on one under way.
enum Turn {
    Lead(Arc<InFlight>),
    Wait(Arc<InFlight>),
}

/// Returns the URL of the public key end point for the OWID using the scheme
/// provided, normally `https`.
///
/// The OWID's own date is sent as the `date` parameter, counted in whole
/// minutes from 2020-01-01, so that a creator which rotates its key returns
/// the key that was in force when this OWID was signed. Creators rotate
/// weekly, so without the date only identifiers created since the most
/// recent rotation can be verified, and every older one is reported as not
/// matching. A creator that ignores the parameter returns its current key,
/// so every identifier it signed under an earlier key reads as not matching.
/// A creator that rotates its key therefore has to honour the date.
///
/// The date is left out where it cannot be counted, which no OWID read by
/// this crate can be. See `minutes_since_base` in the io module.
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

/// Makes the request through the transport and reads the answer, taking
/// only a 200 as the key.
///
/// A redirect is refused here, whatever the transport, so a creator whose
/// domain answers 3xx has its key reported as unavailable and nothing is
/// ever requested from wherever the redirect pointed. See
/// [`PublicKeyFetch`] for why. Any other status without the key, a 404 for
/// a date the creator cannot serve for example, reaches the caller the same
/// way, as the key being unavailable, which it is.
async fn request_public_key(fetch: &dyn PublicKeyFetch, url: &str) -> Result<String> {
    let response = fetch.fetch(url).await?;
    if (300..400).contains(&response.status) {
        return Err(Error::Http(format!(
            "the public key end point answered a redirect ({}) for {url}, which is never followed",
            response.status
        )));
    }
    if response.status != 200 {
        return Err(Error::Http(format!(
            "the public key end point answered {} for {url}",
            response.status
        )));
    }
    Ok(response.body)
}

/// Fetches the public key PEM for the URL, from the cache when the creator
/// has already confirmed a key for the minute the URL names, from a fetch
/// already under way for the same URL when there is one, and otherwise
/// through the transport.
async fn public_key_pem(fetch: &dyn PublicKeyFetch, url: &str) -> Result<String> {
    let end_point = end_point_of(url);
    let minute = minute_of(url);
    loop {
        // The lock is taken and released before anything is awaited, so no
        // caller ever holds it across a fetch.
        let turn = {
            let mut held = cache();
            if let Some(pem) = minute.and_then(|minute| held.held_pem(end_point, minute)) {
                return Ok(pem);
            }
            match held.in_flight.get(url) {
                Some(in_flight) => Turn::Wait(Arc::clone(in_flight)),
                None => {
                    let in_flight = Arc::new(InFlight::default());
                    held.in_flight
                        .insert(url.to_owned(), Arc::clone(&in_flight));
                    Turn::Lead(in_flight)
                }
            }
        };
        match turn {
            Turn::Wait(in_flight) => match in_flight.finished().await {
                Some(Ok(pem)) => return Ok(pem),
                Some(Err(message)) => return Err(Error::Http(message)),
                // The caller making the fetch was dropped before it ended,
                // so go round again and make it.
                None => continue,
            },
            Turn::Lead(in_flight) => {
                let mut leader = Leader {
                    url,
                    in_flight,
                    outcome: None,
                };
                let result = request_public_key(fetch, url).await;
                leader.outcome = Some(match &result {
                    Ok(pem) => {
                        // Held before the leader is dropped, so a caller
                        // arriving between the two finds the key rather
                        // than starting a fetch of its own.
                        if let Some(minute) = minute {
                            cache().hold(end_point, minute, pem);
                        }
                        Ok(pem.clone())
                    }
                    Err(Error::Http(message)) => Err(message.clone()),
                    Err(other) => Err(other.to_string()),
                });
                return result;
            }
        }
    }
}

impl Owid {
    /// Verifies this OWID, and any others that were included when it was
    /// signed, by fetching the public key from the domain associated with
    /// the OWID through the transport provided. The scheme is normally
    /// `https`.
    ///
    /// The request is the one [`public_key_url`] builds, so it names the
    /// minute the OWID was created and a creator that rotates its key
    /// answers with the key in force then. Only a 200 is taken as the key.
    /// A redirect is never followed, whatever the transport does, because a
    /// key from wherever a redirect points is not the creator's key. Keys
    /// are held against the span of minutes the creator has confirmed them
    /// for, so an OWID dated inside a confirmed span is verified without a
    /// request, and a caller that asks for a key while another caller is
    /// fetching it waits for that fetch.
    ///
    /// The future is not `Send`, so it can be driven by a single threaded
    /// host and by a transport tied to one thread, and it needs no
    /// particular runtime.
    ///
    /// Pass an empty slice for `others` when the OWID was signed on its own.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the public key can not be fetched, or any
    /// error from [`Owid::verify_with_public_key`].
    ///
    /// # Examples
    ///
    /// ```
    /// use owid::{Owid, PublicKeyFetch, SignatureStatus};
    ///
    /// async fn check(fetch: &dyn PublicKeyFetch, encoded: &str) -> SignatureStatus {
    ///     match Owid::from_base64(encoded) {
    ///         Ok(owid) => owid.verify_status(fetch, "https", &[]).await,
    ///         Err(_) => SignatureStatus::VerificationError,
    ///     }
    /// }
    /// ```
    pub async fn verify(
        &self,
        fetch: &dyn PublicKeyFetch,
        scheme: &str,
        others: &[&Owid],
    ) -> Result<bool> {
        self.verify_at_url(fetch, &public_key_url(self, scheme), others)
            .await
    }

    /// The work [`Owid::verify`] does once the URL is known, kept apart so
    /// that the tests drive the same fetch and check against a key end
    /// point they can stand up locally, rather than a near copy of it.
    pub(crate) async fn verify_at_url(
        &self,
        fetch: &dyn PublicKeyFetch,
        url: &str,
        others: &[&Owid],
    ) -> Result<bool> {
        let pem = public_key_pem(fetch, url).await?;
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
    pub async fn verify_status(
        &self,
        fetch: &dyn PublicKeyFetch,
        scheme: &str,
        others: &[&Owid],
    ) -> SignatureStatus {
        SignatureStatus::of(self.verify(fetch, scheme, others).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::creator::Creator;
    use crate::crypto::Crypto;
    use crate::io::{
        base_date, minutes_since_base, write_byte, write_byte_array, write_date, write_domain,
        write_signature,
    };
    use crate::version::Version;
    use crate::SIGNATURE_LENGTH;
    use chrono::{DateTime, Duration, Utc};
    use std::rc::Rc;
    use std::sync::Mutex;

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

    /// The moment the stand in end point treats as now, ten days after the
    /// fixture identifier was signed. See [`end_point_answer`].
    fn request_moment() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-14T00:00:00Z")
            .expect("should read the request moment")
            .with_timezone(&Utc)
    }

    /// The value of a query parameter in a URL or request target, or `None`
    /// where it does not carry it.
    fn query_value(target: &str, name: &str) -> Option<String> {
        target
            .split_once('?')?
            .1
            .split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{name}=")))
            .map(str::to_owned)
    }

    /// Answers a public key request the way the cloud controller does. A
    /// request naming a date is served the key that was in force then, a
    /// request without one is served the key in force at the moment of the
    /// request, a date in the future is read as that moment, a date the
    /// schedule does not reach is a 404, and a date that is not a number is
    /// a 400.
    ///
    /// The moment of the request is fixed at [`request_moment`] so the
    /// tests are repeatable. It sits ten days after the fixture identifier
    /// was signed, so an undated request is served a key other than the one
    /// that signed it, exactly as it would be against the live creator in
    /// the week that followed.
    fn end_point_answer(schedule: &[ScheduledKey], target: &str) -> FetchResponse {
        let asked = match query_value(target, "date") {
            None => Some(request_moment()),
            Some(minutes) => minutes
                .parse::<i64>()
                .ok()
                .map(|minutes| (base_date() + Duration::minutes(minutes)).min(request_moment())),
        };
        let key = asked.and_then(|at| key_in_force(schedule, at));
        let (status, body) = match (asked, key) {
            (None, _) => (400, String::new()),
            (Some(_), Some(key)) => (200, key.pem.clone()),
            (Some(_), None) => (404, String::new()),
        };
        FetchResponse { status, body }
    }

    /// What a [`Stub`] answers a URL with.
    type Answer = Box<dyn Fn(&str) -> Result<FetchResponse> + Send + Sync>;

    /// A transport that answers without any network, recording every URL it
    /// was asked for so a test can say what was requested and what was not.
    ///
    /// Every answer is given after yielding once, so two callers that ask
    /// at the same time both reach the point of asking before either is
    /// answered, which is what the sharing of a fetch is measured against.
    struct Stub {
        answer: Answer,
        requests: Mutex<Vec<String>>,
    }

    impl Stub {
        fn new(answer: impl Fn(&str) -> Result<FetchResponse> + Send + Sync + 'static) -> Stub {
            Stub {
                answer: Box::new(answer),
                requests: Mutex::new(Vec::new()),
            }
        }

        /// A stand in for the creator public key end point, answering the
        /// way the cloud controller does. See [`end_point_answer`].
        fn end_point() -> Stub {
            let schedule = schedule();
            Stub::new(move |url| Ok(end_point_answer(&schedule, url)))
        }

        /// Every URL requested so far, in order.
        fn requests(&self) -> Vec<String> {
            self.requests
                .lock()
                .expect("should lock the record of requests")
                .clone()
        }

        /// The date parameter of every request so far, in order, so a test
        /// can say what went over the wire rather than only what the URL
        /// builder returned.
        fn dates(&self) -> Vec<Option<String>> {
            self.requests()
                .iter()
                .map(|url| query_value(url, "date"))
                .collect()
        }
    }

    impl PublicKeyFetch for Stub {
        fn fetch<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<FetchResponse>> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .expect("should lock the record of requests")
                    .push(url.to_owned());
                tokio::task::yield_now().await;
                (self.answer)(url)
            })
        }
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

    /// An identifier with the version, domain and date given and a signature
    /// of zeroes, for the cases that are about the URL rather than the
    /// signature. Reading it back is the only way an identifier reaches a
    /// caller, so the bytes are written and then parsed.
    fn crafted(version: Version, domain: &str, minutes: u32) -> Owid {
        let mut buffer = Vec::new();
        write_byte(&mut buffer, version.as_byte());
        write_domain(&mut buffer, domain).expect("should write the domain");
        write_date(
            &mut buffer,
            &(base_date() + Duration::minutes(i64::from(minutes))),
            version,
        )
        .expect("should write the date");
        write_byte_array(&mut buffer, &[]).expect("should write the payload");
        write_signature(&mut buffer, &[0u8; SIGNATURE_LENGTH]).expect("should write the signature");
        Owid::from_byte_array(&buffer).expect("should read the crafted identifier")
    }

    /// The version segment is the identifier's own version byte, so a
    /// version 2 identifier asks the version 2 end point. Nothing else in
    /// this suite carries a version other than 3, so this is the test that
    /// catches a constant put back into the path.
    #[test]
    fn url_names_the_version_the_identifier_carries() {
        let owid = crafted(Version::Version2, "example.com", IDENTIFIER_MINUTES);
        assert_eq!(
            owid.version().as_byte(),
            2,
            "the crafted identifier is version 2"
        );
        assert_eq!(
            public_key_url(&owid, "https"),
            format!(
                "https://example.com/owid/api/v2/public-key?date={IDENTIFIER_MINUTES}&format=pkcs"
            ),
            "should ask the version 2 end point"
        );
    }

    /// Keys are held against the span of minutes the creator confirmed them
    /// for, so two identifiers from different weeks fetch two different
    /// keys, and a key held for one week never answers for another.
    ///
    /// The scheme is one no other test uses, because the cache is shared by
    /// every test in the process and is keyed by the end point, which the
    /// scheme is part of.
    #[tokio::test]
    async fn keys_are_held_per_request_and_not_per_domain() {
        let _serialised = CACHE_TESTS.lock().await;
        let stub = Stub::end_point();
        let earlier = crafted(
            Version::Version3,
            "51d.es",
            IDENTIFIER_MINUTES - 14 * 24 * 60,
        );
        let later = crafted(Version::Version3, "51d.es", IDENTIFIER_MINUTES);
        let first = public_key_pem(&stub, &public_key_url(&earlier, "stub-held"))
            .await
            .expect("should fetch the earlier week's key");
        let second = public_key_pem(&stub, &public_key_url(&later, "stub-held"))
            .await
            .expect("should fetch the later week's key");
        assert_ne!(first, second, "two weeks, two keys");
        assert_eq!(stub.requests().len(), 2, "one request per week");
        let again = public_key_pem(&stub, &public_key_url(&earlier, "stub-held"))
            .await
            .expect("should answer from what is held");
        assert_eq!(
            again, first,
            "the held key is the one fetched for that week"
        );
        assert_eq!(
            stub.requests().len(),
            2,
            "a week already held is not asked for again"
        );
    }

    /// The minute count for a moment, counted the way the key URL counts it.
    fn minutes_at(moment: &str) -> u32 {
        let moment = DateTime::parse_from_rfc3339(moment)
            .expect("should read the moment")
            .with_timezone(&Utc);
        minutes_since_base(&moment).expect("should count the minutes")
    }

    /// The PEM the fetch answers for an identifier from 51d.es dated at the
    /// minute, asked through the scheme given.
    async fn pem_at(stub: &Stub, scheme: &str, minutes: u32) -> String {
        let owid = crafted(Version::Version3, "51d.es", minutes);
        public_key_pem(stub, &public_key_url(&owid, scheme))
            .await
            .expect("should answer with a key")
    }

    /// The PEM the published schedule says was in force at the minute.
    fn in_force_at(schedule: &[ScheduledKey], minutes: u32) -> String {
        key_in_force(
            schedule,
            base_date() + Duration::minutes(i64::from(minutes)),
        )
        .expect("the schedule should reach the minute")
        .pem
        .clone()
    }

    /// How many keys the cache holds in all.
    fn held_keys() -> usize {
        cache().held
    }

    /// How many keys the cache holds for the 51d.es end point asked through
    /// the scheme. The cache is shared by every test in the process and the
    /// harness runs them in parallel, so a count over the whole cache would
    /// see the keys other tests are fetching at the same moment.
    fn held_keys_at(scheme: &str) -> usize {
        cache()
            .keys
            .get(&format!("{scheme}://51d.es/owid/api/v3/public-key"))
            .map_or(0, Vec::len)
    }

    /// A key the creator has confirmed for two minutes is served for every
    /// minute between them without a request, because a key is in force from
    /// the start of its period until the next key starts. A minute outside
    /// every confirmed span is asked about.
    #[tokio::test]
    async fn a_minute_between_two_confirmed_minutes_is_served_from_the_cache() {
        let _serialised = CACHE_TESTS.lock().await;
        clear_cache();
        let stub = Stub::end_point();
        // The week of 31 August 2026, which the fixture identifier was
        // signed in, and which is wholly in the past so the cache reads each
        // minute as itself rather than as now.
        let first = minutes_at("2026-08-31T00:01:00Z");
        let last = minutes_at("2026-09-06T23:00:00Z");
        let pem = pem_at(&stub, "stub-span", first).await;
        assert_eq!(
            pem_at(&stub, "stub-span", last).await,
            pem,
            "one key covers the week"
        );
        assert_eq!(
            stub.requests().len(),
            2,
            "the two ends of the span were asked about"
        );
        for between in [first + 1, first + 3 * 24 * 60, last - 1] {
            assert_eq!(
                pem_at(&stub, "stub-span", between).await,
                pem,
                "the key served for minute {between}"
            );
        }
        assert_eq!(
            stub.requests().len(),
            2,
            "a minute between two confirmed minutes is not asked about"
        );
        assert_eq!(
            held_keys_at("stub-span"),
            1,
            "one key is held however many minutes it covers"
        );
        assert_ne!(
            pem_at(&stub, "stub-span", first - 2).await,
            pem,
            "a minute in the week before is the earlier week's key"
        );
        assert_eq!(
            stub.requests().len(),
            3,
            "a minute before the span is asked about"
        );
        assert_eq!(
            held_keys_at("stub-span"),
            2,
            "the earlier week's key is held as a second key"
        );
    }

    /// The case that made the cache almost useless when it was keyed by the
    /// whole URL. A hundred identifiers with a hundred different minutes
    /// inside one key's period cost a hundred requests then. With the ends
    /// of the period confirmed they cost none.
    #[tokio::test]
    async fn a_hundred_identifiers_in_one_confirmed_period_make_no_request() {
        let _serialised = CACHE_TESTS.lock().await;
        clear_cache();
        let stub = Stub::end_point();
        let start = minutes_at("2026-09-01T00:00:00Z");
        pem_at(&stub, "stub-hundred", start).await;
        pem_at(&stub, "stub-hundred", start + 100).await;
        for i in 1..=100 {
            pem_at(&stub, "stub-hundred", start + i).await;
        }
        assert_eq!(
            stub.requests().len(),
            2,
            "a hundred identifiers over a hundred minutes made no request once both ends of the span were known"
        );
    }

    /// A key is only ever served for a minute inside the span the creator
    /// has confirmed it for. Where the creator rotated between two confirmed
    /// minutes, the minutes between them belong to neither key until the
    /// creator is asked, and every answer agrees with the published
    /// schedule.
    #[tokio::test]
    async fn a_key_is_never_served_for_a_minute_outside_its_confirmed_span() {
        let _serialised = CACHE_TESTS.lock().await;
        clear_cache();
        let schedule = schedule();
        let stub = Stub::end_point();
        let rotation = minutes_at("2026-08-31T00:00:00Z");
        let week = 7 * 24 * 60;
        // The start of the week before the rotation and the end of the week
        // after it, so the two keys are held with the rotation between.
        pem_at(&stub, "stub-rotation", rotation - week).await;
        pem_at(&stub, "stub-rotation", rotation + week - 1).await;
        assert_eq!(stub.requests().len(), 2);
        assert_eq!(held_keys_at("stub-rotation"), 2);

        // Every minute across the rotation, in an order that walks in from
        // both sides, is answered with the key the schedule gives, whether
        // from the cache or by asking.
        let minutes = [
            rotation - 1,
            rotation,
            rotation - 2,
            rotation + 1,
            rotation - week / 2,
            rotation + week / 2,
            rotation - 3,
            rotation + 2,
            rotation - 1,
            rotation,
        ];
        for minute in minutes {
            assert_eq!(
                pem_at(&stub, "stub-rotation", minute).await,
                in_force_at(&schedule, minute),
                "the key served for minute {minute}"
            );
        }
        assert_eq!(
            held_keys_at("stub-rotation"),
            2,
            "two keys are held, each with its own span"
        );
        let asked = stub.requests().len();
        assert!(
            asked > 2 && asked < 2 + minutes.len(),
            "some minutes were asked about and some were served: {asked}"
        );

        // The minute either side of the rotation is now confirmed, so
        // nothing across the whole fortnight needs asking.
        let mut minute = rotation - week;
        while minute < rotation + week {
            assert_eq!(
                pem_at(&stub, "stub-rotation", minute).await,
                in_force_at(&schedule, minute),
                "the key served for minute {minute}"
            );
            minute += 60;
        }
        assert_eq!(
            stub.requests().len(),
            asked,
            "both spans are fully confirmed, so nothing was asked"
        );
    }

    /// A minute within the clock drift allowance of now, or later, is asked
    /// about every time and never held, because a creator whose clock
    /// differs from this one's may have read it as its present rather than
    /// as the minute named. A minute beyond the allowance is held as usual.
    /// Live identifiers therefore cost one request per minute per creator,
    /// as they always did, and older ones cost none.
    #[tokio::test]
    async fn a_minute_within_the_drift_allowance_is_not_held() {
        let _serialised = CACHE_TESTS.lock().await;
        clear_cache();
        let stub = Stub::end_point();
        let started = minutes_since_base(&Utc::now()).expect("should count now");
        let recent = started - 1;
        pem_at(&stub, "stub-drift", recent).await;
        pem_at(&stub, "stub-drift", recent).await;
        pem_at(&stub, "stub-drift", started + 7 * 24 * 60).await;
        public_key_pem(
            &stub,
            "stub-drift://51d.es/owid/api/v3/public-key?format=pkcs",
        )
        .await
        .expect("should answer with the key in force now");
        let old = started - CLOCK_DRIFT_ALLOWANCE_MINUTES - 1;
        pem_at(&stub, "stub-drift", old).await;
        pem_at(&stub, "stub-drift", old).await;
        if minutes_since_base(&Utc::now()) != Some(started) {
            // The minute changed during the test, so the calls were not all
            // about the same now and the count says nothing.
            return;
        }
        assert_eq!(
            stub.requests().len(),
            5,
            "the recent minute was asked about twice, the future minute and the request with no date once each, and the old minute once with the second call held"
        );
        assert_eq!(
            held_keys_at("stub-drift"),
            1,
            "only the old minute's key is held"
        );
    }

    /// The cache does not grow without limit. The number of distinct keys a
    /// verifier is shown is chosen by whoever presents the identifiers rather
    /// than by this process, so the stand in creator here answers every
    /// minute with a different key, which is the worst a creator can do to
    /// the cache.
    #[tokio::test]
    async fn the_cache_is_bounded() {
        let _serialised = CACHE_TESTS.lock().await;
        clear_cache();
        let stub = Stub::new(|url| {
            let minute = query_value(url, "date").expect("every request here is dated");
            Ok(FetchResponse {
                status: 200,
                body: format!("-----BEGIN PUBLIC KEY-----\n{minute}\n-----END PUBLIC KEY-----\n"),
            })
        });
        for minute in 0..=MAXIMUM_CACHED_KEYS {
            pem_at(&stub, "stub-bounded", minute as u32).await;
        }
        assert_eq!(
            stub.requests().len(),
            MAXIMUM_CACHED_KEYS + 1,
            "every minute was a different key, so every one was asked"
        );
        assert!(
            held_keys() <= MAXIMUM_CACHED_KEYS,
            "held {} of at most {MAXIMUM_CACHED_KEYS}",
            held_keys()
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

    /// The key in force in the following week does not verify it, which is
    /// the whole reason the date has to be sent. Keys rotate weekly, so the
    /// key in force when an identifier is checked is not the key that signed
    /// it unless the check happens in the same week.
    #[test]
    fn a_later_weeks_key_does_not_verify_an_earlier_weeks_identifier() {
        let owid = identifier();
        let schedule = schedule();
        let later = key_in_force(&schedule, request_moment())
            .expect("the schedule covers the moment of the request");
        assert!(
            later.starts_at > owid.date(),
            "the key in force in the following week starts after the identifier"
        );
        assert_eq!(
            owid.verify_status_with_public_key(&later.pem, &[]),
            SignatureStatus::Invalid,
            "a later week's key should not verify an earlier week's identifier"
        );
    }

    /// The fetch asks for the key in force when the identifier was signed and
    /// verifies it, with the identifier signed in a week earlier than the one
    /// the end point counts as current. This is the case the missing date
    /// parameter broke, and it fails without the fix.
    #[tokio::test]
    async fn dated_fetch_verifies_an_identifier_from_an_earlier_key_week() {
        let owid = identifier();
        let stub = Stub::end_point();
        assert!(
            owid.verify(&stub, "stub-dated", &[])
                .await
                .expect("should fetch the key and check the signature"),
            "should verify against the key in force when it was signed"
        );
        assert_eq!(
            stub.dates(),
            vec![Some(IDENTIFIER_MINUTES.to_string())],
            "the request should name the minute the identifier was created"
        );
    }

    /// The same identifier against the same end point without the date, which
    /// is the request this crate made before the fix. The end point answers
    /// with the key in force at the moment of the request, ten days after the
    /// identifier was signed, the signature does not match it, and a genuine
    /// identifier reads as a forgery.
    #[tokio::test]
    async fn undated_fetch_leaves_an_earlier_weeks_identifier_unverified() {
        let owid = identifier();
        let stub = Stub::end_point();
        let undated = format!(
            "stub-undated://{}/owid/api/v{}/public-key?format=pkcs",
            owid.domain(),
            owid.version().as_byte()
        );
        assert_eq!(
            SignatureStatus::of(owid.verify_at_url(&stub, &undated, &[]).await),
            SignatureStatus::Invalid,
            "an undated request gets the key in force at the request, which did not sign it"
        );
        assert_eq!(
            stub.dates(),
            vec![None],
            "the request should carry no date, as it did before the fix"
        );
    }

    /// A creator whose domain answers with a redirect does not get the key
    /// at the other end trusted as its own. The other end here serves the
    /// genuine schedule, so following the redirect would read as valid, and
    /// refusing it must read as the key being unavailable with the request
    /// to the other host never made. Without this a network attacker able
    /// to bend a creator's DNS, or a misconfigured creator, could substitute
    /// the key and forgeries would verify.
    ///
    /// The refusal is this crate's and not the transport's, so it holds for
    /// every transport. The built in one is shown refusing on its own
    /// account in [`reqwest_fetch_does_not_follow_a_redirect`].
    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let owid = identifier();
        let creator = public_key_url(&owid, "stub-redirect");
        let schedule = schedule();
        let stub = Stub::new({
            let creator = creator.clone();
            move |url| {
                if url == creator {
                    Ok(FetchResponse {
                        status: 302,
                        body: String::new(),
                    })
                } else {
                    Ok(end_point_answer(&schedule, url))
                }
            }
        });
        assert_eq!(
            owid.verify_status(&stub, "stub-redirect", &[]).await,
            SignatureStatus::KeyUnavailable,
            "a redirect is the key being unavailable, never a key from wherever it points"
        );
        assert_eq!(
            stub.requests(),
            vec![creator],
            "the request that would have gone to the other host was never made"
        );
    }

    /// An end point that cannot serve a key for the date leaves the signature
    /// unjudged rather than reporting it as a forgery.
    #[tokio::test]
    async fn a_key_the_end_point_cannot_serve_is_key_unavailable() {
        let owid = identifier();
        let stub = Stub::end_point();
        // A fortnight before the schedule begins, which no key in it covers,
        // so the end point answers 404 the way the cloud does.
        let before = minutes_since_base(&(schedule()[0].starts_at - Duration::days(14)))
            .expect("should count the minutes");
        let url = format!(
            "stub-unserved://{}/owid/api/v{}/public-key?date={}&format=pkcs",
            owid.domain(),
            owid.version().as_byte(),
            before
        );
        assert_eq!(
            SignatureStatus::of(owid.verify_at_url(&stub, &url, &[]).await),
            SignatureStatus::KeyUnavailable,
            "no key means the signature was never examined"
        );
    }

    /// A transport that obtained no answer at all, because the name did not
    /// resolve or the connection failed, is the key being unavailable too.
    #[tokio::test]
    async fn a_transport_that_obtains_no_answer_is_key_unavailable() {
        let stub = Stub::new(|url| Err(Error::Http(format!("no route to {url}"))));
        assert_eq!(
            identifier()
                .verify_status(&stub, "stub-unreachable", &[])
                .await,
            SignatureStatus::KeyUnavailable,
            "a key that could not be fetched should not read as a forgery"
        );
    }

    /// Two callers that ask for one key at the same time make one request
    /// between them. The second finds the first's fetch under way and waits
    /// for it, and both verify.
    #[tokio::test]
    async fn callers_asking_for_one_key_at_the_same_time_share_one_fetch() {
        let owid = identifier();
        let stub = Stub::end_point();
        let (first, second) = tokio::join!(
            owid.verify_status(&stub, "stub-shared", &[]),
            owid.verify_status(&stub, "stub-shared", &[])
        );
        assert_eq!(
            (first, second),
            (SignatureStatus::Valid, SignatureStatus::Valid),
            "both callers should verify against the one key fetched"
        );
        assert_eq!(
            stub.requests().len(),
            1,
            "the second caller should wait for the first caller's fetch"
        );
    }

    /// Serialises the tests that depend on the process wide key cache.
    ///
    /// The harness runs tests in parallel, so a test that empties the cache
    /// would otherwise be able to do so in the middle of a test that is
    /// counting requests and expecting a key it fetched to still be held.
    static CACHE_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A key already held is used without asking again, and emptying the
    /// cache makes the next caller ask. This is how a process drops a key it
    /// has learned it should no longer trust.
    #[tokio::test]
    async fn clearing_the_cache_makes_the_next_caller_fetch_again() {
        let _serialised = CACHE_TESTS.lock().await;
        let owid = identifier();
        let stub = Stub::end_point();

        assert_eq!(
            owid.verify_status(&stub, "stub-cleared", &[]).await,
            SignatureStatus::Valid
        );
        assert_eq!(
            owid.verify_status(&stub, "stub-cleared", &[]).await,
            SignatureStatus::Valid
        );
        assert_eq!(
            stub.requests().len(),
            1,
            "the second caller should be answered from the cache"
        );

        clear_cache();

        assert_eq!(
            owid.verify_status(&stub, "stub-cleared", &[]).await,
            SignatureStatus::Valid
        );
        assert_eq!(
            stub.requests().len(),
            2,
            "the cache was emptied so the key should be asked for again"
        );
    }

    /// A caller that is dropped part way through its fetch does not leave
    /// the callers waiting on it hanging. They are woken, find no fetch
    /// under way, and make the request themselves.
    #[tokio::test]
    async fn a_fetch_dropped_part_way_is_made_again_by_the_caller_waiting_on_it() {
        let owid = identifier();
        let stub = Stub::end_point();
        let mut context = Context::from_waker(Waker::noop());
        let mut first = Box::pin(owid.verify_status(&stub, "stub-dropped", &[]));
        assert!(
            first.as_mut().poll(&mut context).is_pending(),
            "the first caller is part way through its fetch"
        );
        let mut second = Box::pin(owid.verify_status(&stub, "stub-dropped", &[]));
        assert!(
            second.as_mut().poll(&mut context).is_pending(),
            "the second caller is waiting on the first"
        );
        assert_eq!(stub.requests().len(), 1, "one fetch is under way");
        drop(first);
        assert_eq!(
            second.await,
            SignatureStatus::Valid,
            "the second caller should verify against a key it fetched itself"
        );
        assert_eq!(
            stub.requests().len(),
            2,
            "the second caller made the request the first never finished"
        );
    }

    /// A transport whose future holds an `Rc` across an await, which the
    /// compiler refuses in a `Send` future. That this compiles is the proof
    /// that neither the trait nor the verification asks for `Send`, which
    /// is what lets a single threaded host, such as a WebAssembly one,
    /// provide the transport.
    struct ThreadBound {
        pem: String,
    }

    impl PublicKeyFetch for ThreadBound {
        fn fetch<'a>(&'a self, _url: &'a str) -> LocalBoxFuture<'a, Result<FetchResponse>> {
            Box::pin(async move {
                let held = Rc::new(self.pem.clone());
                tokio::task::yield_now().await;
                Ok(FetchResponse {
                    status: 200,
                    body: held.as_str().to_owned(),
                })
            })
        }
    }

    /// See [`ThreadBound`]. The test body holds an `Rc` across the await as
    /// well, so the verification future is shown not to need `Send` either.
    #[tokio::test]
    async fn the_transport_future_is_not_required_to_be_send() {
        let owid = identifier();
        let schedule = schedule();
        let key = key_in_force(&schedule, owid.date()).expect("the schedule covers the date");
        let transport = ThreadBound {
            pem: key.pem.clone(),
        };
        let marker = Rc::new(());
        let status = owid
            .verify_status(&transport, "stub-thread-bound", &[])
            .await;
        assert_eq!(
            Rc::strong_count(&marker),
            1,
            "the marker lived across the await"
        );
        assert_eq!(
            status,
            SignatureStatus::Valid,
            "a transport tied to one thread should verify like any other"
        );
    }

    /// The tests of the built in transport, which make real HTTP requests
    /// to an end point stood up on the loopback address.
    #[cfg(feature = "reqwest-fetch")]
    mod reqwest {
        use super::*;
        use crate::ReqwestFetch;
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::Arc;
        use std::thread;

        /// A stand in for the creator public key end point over HTTP,
        /// answering as [`end_point_answer`] does and recording the date
        /// parameter of every request.
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
                // The thread ends when the test binary does. Nothing outlives
                // the process, and stopping the listener would mean
                // synchronising with a thread blocked in accept for no gain.
                thread::spawn(move || {
                    let schedule = schedule();
                    for stream in listener.incoming() {
                        let mut stream = match stream {
                            Ok(stream) => stream,
                            Err(_) => break,
                        };
                        let target = read_request_target(&stream);
                        seen.lock()
                            .expect("should lock the record of requests")
                            .push(query_value(&target, "date"));
                        let answer = end_point_answer(&schedule, &target);
                        let reason = match answer.status {
                            200 => "OK",
                            400 => "Bad Request",
                            _ => "Not Found",
                        };
                        let response = format!(
                            "HTTP/1.1 {} {reason}\r\nContent-Type: text/plain\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                            answer.status,
                            answer.body.len(),
                            answer.body
                        );
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

            /// The URL a fetch would use, with the creator host replaced by
            /// this server. The path and query are the ones the crate
            /// builds, so what is under test is the real URL rather than a
            /// copy of it.
            fn url_for(&self, owid: &Owid) -> String {
                let built = public_key_url(owid, "http");
                let path = built
                    .split_once(owid.domain())
                    .expect("the URL carries the creator domain")
                    .1;
                format!("{}{}", self.base, path)
            }
        }

        /// Reads the request line and drains the headers, which are not
        /// used and are read so the client is not left writing into a
        /// connection nobody is draining, then returns the request target.
        fn read_request_target(stream: &std::net::TcpStream) -> String {
            let mut reader =
                BufReader::new(stream.try_clone().expect("should clone the connection"));
            let mut request = String::new();
            reader
                .read_line(&mut request)
                .expect("should read the request line");
            loop {
                let mut header = String::new();
                let read = reader
                    .read_line(&mut header)
                    .expect("should read a header line");
                if read == 0 || header.trim().is_empty() {
                    break;
                }
            }
            request.split_whitespace().nth(1).unwrap_or("").to_owned()
        }

        /// The built in transport makes the dated request over HTTP and the
        /// genuine identifier verifies against the key it is served.
        #[tokio::test]
        async fn reqwest_fetch_verifies_the_genuine_identifier_over_http() {
            let owid = identifier();
            let server = KeyServer::start();
            let fetch = ReqwestFetch::new().expect("should build the transport");
            assert!(
                owid.verify_at_url(&fetch, &server.url_for(&owid), &[])
                    .await
                    .expect("should fetch the key and check the signature"),
                "should verify against the key in force when it was signed"
            );
            assert_eq!(
                server.dates(),
                vec![Some(IDENTIFIER_MINUTES.to_string())],
                "the request should name the minute the identifier was created"
            );
        }

        /// The built in transport refuses a redirect on its own account, so
        /// even the request to the other host is never made. The other host
        /// here serves the genuine schedule, so following would read as
        /// valid.
        #[tokio::test]
        async fn reqwest_fetch_does_not_follow_a_redirect() {
            let owid = identifier();
            let elsewhere = KeyServer::start();
            let location = elsewhere.url_for(&owid);
            let listener = TcpListener::bind("127.0.0.1:0").expect("should bind the creator");
            let creator = format!(
                "http://{}",
                listener.local_addr().expect("should have an address")
            );
            thread::spawn(move || {
                for stream in listener.incoming() {
                    let mut stream = match stream {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    read_request_target(&stream);
                    let response = format!(
                        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
                         Connection: close\r\n\r\n"
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
            });
            let url = format!(
                "{}/owid/api/v{}/public-key?format=pkcs",
                creator,
                owid.version().as_byte()
            );
            let fetch = ReqwestFetch::new().expect("should build the transport");
            assert_eq!(
                SignatureStatus::of(owid.verify_at_url(&fetch, &url, &[]).await),
                SignatureStatus::KeyUnavailable,
                "a redirect is the key being unavailable, never a key from wherever it points"
            );
            assert!(
                elsewhere.dates().is_empty(),
                "the request that would have gone to the other host was never made"
            );
        }

        /// A 404 from a real end point reaches the caller as the key being
        /// unavailable.
        #[tokio::test]
        async fn reqwest_fetch_reports_a_key_the_end_point_cannot_serve() {
            let owid = identifier();
            let server = KeyServer::start();
            let before = minutes_since_base(&(schedule()[0].starts_at - Duration::days(14)))
                .expect("should count the minutes");
            let url = format!(
                "{}/owid/api/v{}/public-key?date={}&format=pkcs",
                server.base,
                owid.version().as_byte(),
                before
            );
            let fetch = ReqwestFetch::new().expect("should build the transport");
            assert_eq!(
                SignatureStatus::of(owid.verify_at_url(&fetch, &url, &[]).await),
                SignatureStatus::KeyUnavailable,
                "no key means the signature was never examined"
            );
        }
    }
}

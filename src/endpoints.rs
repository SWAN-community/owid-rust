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

//! Helpers for hosting the well known end point required by the OWID
//! specification. These are framework agnostic. They return the path and
//! body so that any HTTP server, including WebAssembly edge runtimes, can
//! serve it.
//!
//! The mandatory end point is `/owid/api/v{version}/public-key`, returning
//! a JSON object carrying the public key, the encoding it is in and the
//! moments it is valid from and to. The `format` query parameter, where
//! present, must be `spki`, the only encoding the specification defines,
//! and any other value is answered 400.

use chrono::{DateTime, Duration, Utc};

use crate::creator::Creator;
use crate::error::{Error, Result};
use crate::io::base_date;
use crate::key_answer::PublicKeyAnswer;
use crate::schedule::PublicKeySchedule;
use crate::version::Version;

/// Returns the path of the public key end point for the version provided.
/// For example `/owid/api/v3/public-key`.
pub fn public_key_path(version: Version) -> String {
    format!("/owid/api/v{}/public-key", version.as_byte())
}

/// The JSON body of the public key end point for a creator with one key and
/// no schedule. The key is stated as `publicKey` in the `spki` encoding,
/// which `format` echoes, and both `validFrom` and `validTo` are null,
/// because the creator knows nothing about when the key started or will
/// stop.
///
/// The format is the encoding the request asked for, or `None` where it
/// asked for none, which is read as `spki`. That is the only encoding the
/// specification defines, and a creator answers 400 to any other value.
///
/// # Errors
///
/// Returns [`Error::InvalidKeyFormat`] for a format other than `spki`, which
/// a creator answers as 400, and an error from [`public_key_answer`] where
/// the key cannot be read back.
pub fn public_key_response(creator: &Creator, format: Option<&str>) -> Result<String> {
    if !serves_format(format) {
        return Err(Error::InvalidKeyFormat(
            format.unwrap_or_default().to_owned(),
        ));
    }
    public_key_answer(
        &creator.crypto().subject_public_key_info()?,
        None,
        None,
        None,
    )
}

/// Whether the encoding asked for is the one this crate serves, which a
/// request that names none is read as asking for.
fn serves_format(format: Option<&str>) -> bool {
    format.is_none_or(|format| format == PublicKeyAnswer::SPKI_FORMAT)
}

/// The JSON body of the public key end point for the key and the span it
/// covers, checked with [`PublicKeyAnswer::validate`] first so that a creator
/// never sends an answer it would itself refuse. The moment asked about, where
/// known, is checked against the span as well.
///
/// # Errors
///
/// Returns [`Error::Key`] where the answer would not be valid.
pub fn public_key_answer(
    public_key_pem: &str,
    valid_from: Option<DateTime<Utc>>,
    valid_to: Option<DateTime<Utc>>,
    asked: Option<DateTime<Utc>>,
) -> Result<String> {
    let answer = PublicKeyAnswer::new(public_key_pem, valid_from, valid_to);
    answer.validate(asked)?;
    Ok(answer.to_json())
}

/// The status code and JSON body for the public key end point of a creator
/// that rotates its key, chosen from the schedule the way the specification
/// requires.
///
/// The date parameter is the OWID's own date, counted in whole minutes since
/// 2020-01-01, and the key served is the one in force then, being the latest
/// key whose start is at or before it. A request without a date, or with a
/// date later than the moment of the request, is served the key in force at
/// that moment, so a caller cannot ask for a key whose period has not begun.
/// The format parameter is the encoding the request asked for, or `None`
/// where it asked for none, which is read as `spki`, the only encoding the
/// specification defines. The answer is 200 with the body from
/// [`public_key_answer`], stating the key, its encoding and the moments it
/// is valid from and to, 404 with an empty body where no key is in force at
/// the date, and 400 with an empty body where the format is not `spki` or
/// the date is not a count of minutes.
///
/// # Errors
///
/// Returns [`Error::Key`] where the answer would fail its check, which is a
/// fault in the schedule.
pub fn public_key_response_at(
    schedule: &PublicKeySchedule,
    format: Option<&str>,
    date: Option<&str>,
    now: DateTime<Utc>,
) -> Result<(u16, String)> {
    if !serves_format(format) {
        return Ok((400, String::new()));
    }
    let mut asked = now;
    if let Some(date) = date.filter(|date| !date.is_empty()) {
        let Ok(minutes) = date.parse::<u32>() else {
            return Ok((400, String::new()));
        };
        asked = (base_date() + Duration::minutes(i64::from(minutes))).min(now);
    }
    match schedule.key_in_force(asked) {
        None => Ok((404, String::new())),
        Some(key) => Ok((
            200,
            public_key_answer(
                &key.public_key_pem,
                Some(key.starts_at),
                schedule.next_start_after(key),
                Some(asked),
            )?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    fn new_creator() -> Creator {
        Creator::new("example.com", Crypto::new()).expect("should create the creator")
    }

    /// The public key end point answers in the spki encoding whether the
    /// request asks for it by name or asks for none, echoes the format, and
    /// refuses any other encoding.
    #[test]
    fn public_key_response_formats() {
        let creator = new_creator();
        for format in [Some("spki"), None] {
            let json = public_key_response(&creator, format).expect("should return the public key");
            assert!(json.contains("\"format\":\"spki\""), "{json}");
            let answer = PublicKeyAnswer::parse(&json).expect("should be the JSON form");
            assert_eq!(answer.format, "spki", "the format is echoed");
            assert!(
                answer.valid_from.is_none() && answer.valid_to.is_none(),
                "a single key has no schedule"
            );
            assert!(
                answer.public_key.contains("BEGIN PUBLIC KEY"),
                "should return the PEM for format {format:?}"
            );
        }
        for other in ["pkcs", "other"] {
            assert!(
                matches!(
                    public_key_response(&creator, Some(other)),
                    Err(Error::InvalidKeyFormat(_))
                ),
                "should refuse {other}"
            );
        }
    }

    /// The path must match the well known end point in the specification.
    #[test]
    fn paths() {
        assert_eq!(
            public_key_path(Version::Version3),
            "/owid/api/v3/public-key"
        );
    }

    /// The answer states the moments the key is valid from and to and echoes
    /// the format, the last key of the schedule has no end, an encoding other
    /// than spki is answered 400, and an answer a client would refuse is
    /// refused by the creator first.
    #[test]
    fn response_at_states_the_span_and_is_checked_before_it_is_sent() {
        use crate::crypto::Crypto;
        use crate::schedule::DatedPublicKey;
        use chrono::TimeZone;
        let pem = || {
            Crypto::new()
                .public_key_pem()
                .expect("should export the key")
        };
        let weeks = [
            Utc.with_ymd_and_hms(2026, 8, 24, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 8, 31, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 9, 7, 0, 0, 0).unwrap(),
        ];
        let schedule = PublicKeySchedule::new(
            weeks
                .iter()
                .map(|start| DatedPublicKey::new(*start, pem()))
                .collect(),
        );
        let now = Utc.with_ymd_and_hms(2026, 9, 4, 20, 32, 0).unwrap();
        let minutes = crate::io::minutes_since_base(&now).unwrap().to_string();
        let (status, body) = public_key_response_at(&schedule, Some("spki"), Some(&minutes), now)
            .expect("should answer");
        assert_eq!(status, 200);
        let answer = PublicKeyAnswer::parse(&body).expect("should be the JSON form");
        assert_eq!(answer.format, "spki", "the format is echoed");
        assert_eq!(answer.public_key, schedule.keys()[1].public_key_pem);
        assert_eq!(answer.valid_from, Some(weeks[1]));
        assert_eq!(answer.valid_to, Some(weeks[2]));
        let later = Utc.with_ymd_and_hms(2026, 9, 10, 0, 0, 0).unwrap();
        let (_, body) =
            public_key_response_at(&schedule, None, None, later).expect("should answer");
        assert_eq!(
            PublicKeyAnswer::parse(&body).unwrap().valid_to,
            None,
            "the last key has no end"
        );
        assert_eq!(
            public_key_response_at(&schedule, Some("pkcs"), Some(&minutes), now)
                .unwrap()
                .0,
            400,
            "pkcs is not an encoding the specification defines"
        );
        assert_eq!(
            public_key_response_at(&schedule, None, Some("nonsense"), now)
                .unwrap()
                .0,
            400
        );
        let early = Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap();
        assert_eq!(
            public_key_response_at(
                &schedule,
                None,
                Some(&crate::io::minutes_since_base(&early).unwrap().to_string()),
                now
            )
            .unwrap()
            .0,
            404
        );
        assert!(public_key_answer("not a key", None, None, None).is_err());
        assert!(public_key_answer(&pem(), Some(weeks[1]), Some(weeks[0]), None).is_err());
        assert!(public_key_answer(&pem(), Some(weeks[1]), None, Some(weeks[0])).is_err());
    }
}

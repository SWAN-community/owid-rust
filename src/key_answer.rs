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

//! The JSON body of the public key end point, read and written without any
//! dependency so that both the creator that sends it and the client that
//! reads it, on any target, use the same code and the same checks.

use chrono::{DateTime, SecondsFormat, Utc};

use crate::crypto::Crypto;
use crate::error::{Error, Result};

/// The JSON body of the public key end point. It carries the key together
/// with the moments it is valid from and to, in UTC, so a client holds the
/// key for the whole span from one answer rather than asking again for every
/// minute.
///
/// `valid_from` is `None` where the creator has a single key and no schedule,
/// and `valid_to` is `None` where no later key has been scheduled. Both the
/// creator that sends the answer and the client that reads it check it with
/// [`PublicKeyAnswer::validate`], so a fault in a creator's schedule or store
/// is a server error at the creator rather than a bad answer a client then
/// has to refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyAnswer {
    /// The key in PEM form.
    pub public_key_spki: String,
    /// The UTC moment the key came into force, where known.
    pub valid_from: Option<DateTime<Utc>>,
    /// The UTC moment the next key starts, where one is scheduled.
    pub valid_to: Option<DateTime<Utc>>,
}

impl PublicKeyAnswer {
    /// An answer for the key and the moments it is valid from and to, not
    /// yet checked.
    pub fn new(
        public_key_spki: impl Into<String>,
        valid_from: Option<DateTime<Utc>>,
        valid_to: Option<DateTime<Utc>>,
    ) -> Self {
        PublicKeyAnswer {
            public_key_spki: public_key_spki.into(),
            valid_from,
            valid_to,
        }
    }

    /// Checks the answer the way both the creator that sends it and the
    /// client that reads it must. The key must be a public key this crate
    /// can read, a key valid to a moment must be valid from an earlier one,
    /// and where the moment asked about is known the key must have come into
    /// force by then and, if it has an end, not have ended.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Key`] describing the first check that fails.
    pub fn validate(&self, asked: Option<DateTime<Utc>>) -> Result<()> {
        if self.public_key_spki.trim().is_empty() {
            return Err(Error::Key("the public key answer holds no key".to_owned()));
        }
        Crypto::new_verify_only(&self.public_key_spki).map_err(|_| {
            Error::Key("the public key answer holds a key that cannot be read".to_owned())
        })?;
        if let Some(to) = self.valid_to {
            match self.valid_from {
                None => {
                    return Err(Error::Key(
                        "the public key answer states when the key ends but not when it started"
                            .to_owned(),
                    ))
                }
                Some(from) if to <= from => {
                    return Err(Error::Key(
                        "the public key answer states a key that ends before it starts".to_owned(),
                    ))
                }
                Some(_) => {}
            }
        }
        if let Some(asked) = asked {
            if matches!(self.valid_from, Some(from) if from > asked) {
                return Err(Error::Key(
                    "the public key answer states a key that had not started at the moment asked about"
                        .to_owned(),
                ));
            }
            if matches!(self.valid_to, Some(to) if to <= asked) {
                return Err(Error::Key(
                    "the public key answer states a key that had ended at the moment asked about"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// The answer as JSON, with the moments as RFC 3339 strings in UTC and
    /// `null` where there is no moment.
    pub fn to_json(&self) -> String {
        let mut json = String::from("{\"publicKeySPKI\":");
        write_string(&mut json, &self.public_key_spki);
        json.push_str(",\"validFrom\":");
        write_moment(&mut json, self.valid_from);
        json.push_str(",\"validTo\":");
        write_moment(&mut json, self.valid_to);
        json.push('}');
        json
    }

    /// Reads an answer from its JSON body, not yet checked with
    /// [`PublicKeyAnswer::validate`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Key`] where the body is not a JSON object of the
    /// three fields, each a string or `null`, or a moment is not RFC 3339.
    pub fn parse(json: &str) -> Result<Self> {
        let fields = read_flat_object(json)?;
        let field = |name: &str| {
            fields
                .iter()
                .find(|(key, _)| key == name)
                .and_then(|(_, value)| value.clone())
        };
        let public_key_spki = field("publicKeySPKI").unwrap_or_default();
        Ok(PublicKeyAnswer {
            public_key_spki,
            valid_from: moment(field("validFrom"), "validFrom")?,
            valid_to: moment(field("validTo"), "validTo")?,
        })
    }
}

fn moment(text: Option<String>, field: &str) -> Result<Option<DateTime<Utc>>> {
    match text {
        None => Ok(None),
        Some(text) => DateTime::parse_from_rfc3339(&text)
            .map(|moment| Some(moment.with_timezone(&Utc)))
            .map_err(|_| {
                Error::Key(format!(
                    "the public key answer's {field} is not a moment in UTC"
                ))
            }),
    }
}

fn write_moment(json: &mut String, moment: Option<DateTime<Utc>>) {
    match moment {
        None => json.push_str("null"),
        Some(moment) => write_string(json, &moment.to_rfc3339_opts(SecondsFormat::Secs, true)),
    }
}

fn write_string(json: &mut String, value: &str) {
    json.push('"');
    for c in value.chars() {
        match c {
            '"' => json.push_str("\\\""),
            '\\' => json.push_str("\\\\"),
            '\n' => json.push_str("\\n"),
            '\r' => json.push_str("\\r"),
            '\t' => json.push_str("\\t"),
            c if (c as u32) < 0x20 => json.push_str(&format!("\\u{:04x}", c as u32)),
            c => json.push(c),
        }
    }
    json.push('"');
}

fn not_json() -> Error {
    Error::Key(
        "the public key answer is not the JSON object of three fields the specification requires"
            .to_owned(),
    )
}

/// Reads a JSON object whose values are strings or `null`. Anything else is
/// refused, because the answer has no other shape.
fn read_flat_object(json: &str) -> Result<Vec<(String, Option<String>)>> {
    let chars: Vec<char> = json.chars().collect();
    let mut at = skip_space(&chars, 0);
    if chars.get(at) != Some(&'{') {
        return Err(not_json());
    }
    at = skip_space(&chars, at + 1);
    let mut fields = Vec::new();
    if chars.get(at) == Some(&'}') {
        return if skip_space(&chars, at + 1) == chars.len() {
            Ok(fields)
        } else {
            Err(not_json())
        };
    }
    loop {
        at = skip_space(&chars, at);
        let (name, next) = read_string(&chars, at)?;
        at = skip_space(&chars, next);
        if chars.get(at) != Some(&':') {
            return Err(not_json());
        }
        at = skip_space(&chars, at + 1);
        let value = if chars[at..].starts_with(&['n', 'u', 'l', 'l']) {
            at += 4;
            None
        } else {
            let (value, next) = read_string(&chars, at)?;
            at = next;
            Some(value)
        };
        fields.push((name, value));
        at = skip_space(&chars, at);
        match chars.get(at) {
            Some('}') => {
                at += 1;
                break;
            }
            Some(',') => at += 1,
            _ => return Err(not_json()),
        }
    }
    if skip_space(&chars, at) != chars.len() {
        return Err(not_json());
    }
    Ok(fields)
}

fn skip_space(chars: &[char], mut at: usize) -> usize {
    while at < chars.len() && chars[at].is_whitespace() {
        at += 1;
    }
    at
}

fn read_string(chars: &[char], mut at: usize) -> Result<(String, usize)> {
    if chars.get(at) != Some(&'"') {
        return Err(not_json());
    }
    at += 1;
    let mut value = String::new();
    while at < chars.len() {
        let c = chars[at];
        at += 1;
        if c == '"' {
            return Ok((value, at));
        }
        if c != '\\' {
            value.push(c);
            continue;
        }
        let escaped = *chars.get(at).ok_or_else(not_json)?;
        at += 1;
        match escaped {
            '"' | '\\' | '/' => value.push(escaped),
            'b' => value.push('\u{8}'),
            'f' => value.push('\u{c}'),
            'n' => value.push('\n'),
            'r' => value.push('\r'),
            't' => value.push('\t'),
            'u' => {
                if at + 4 > chars.len() {
                    return Err(not_json());
                }
                let code: String = chars[at..at + 4].iter().collect();
                let code = u32::from_str_radix(&code, 16).map_err(|_| not_json())?;
                value.push(char::from_u32(code).ok_or_else(not_json)?);
                at += 4;
            }
            _ => return Err(not_json()),
        }
    }
    Err(not_json())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn pem() -> String {
        Crypto::new()
            .public_key_pem()
            .expect("should export the key")
    }

    #[test]
    fn writes_and_reads_the_same_answer() {
        let answer = PublicKeyAnswer::new(
            pem(),
            Some(Utc.with_ymd_and_hms(2026, 8, 31, 0, 0, 0).unwrap()),
            Some(Utc.with_ymd_and_hms(2026, 9, 7, 0, 0, 0).unwrap()),
        );
        let json = answer.to_json();
        assert!(
            json.contains("\"validFrom\":\"2026-08-31T00:00:00Z\""),
            "{json}"
        );
        assert_eq!(PublicKeyAnswer::parse(&json).expect("should read"), answer);
        let spanless = PublicKeyAnswer::new(pem(), None, None);
        assert!(spanless.to_json().contains("\"validFrom\":null"));
        assert_eq!(
            PublicKeyAnswer::parse(&spanless.to_json()).expect("should read"),
            spanless
        );
    }

    #[test]
    fn refuses_what_a_client_would_refuse() {
        let from = Utc.with_ymd_and_hms(2026, 8, 31, 0, 0, 0).unwrap();
        let to = Utc.with_ymd_and_hms(2026, 9, 7, 0, 0, 0).unwrap();
        assert!(PublicKeyAnswer::new("not a key", None, None)
            .validate(None)
            .is_err());
        assert!(PublicKeyAnswer::new(pem(), Some(to), Some(from))
            .validate(None)
            .is_err());
        assert!(PublicKeyAnswer::new(pem(), None, Some(to))
            .validate(None)
            .is_err());
        assert!(PublicKeyAnswer::new(pem(), Some(from), Some(to))
            .validate(Some(to))
            .is_err());
        assert!(PublicKeyAnswer::new(pem(), Some(to), None)
            .validate(Some(from))
            .is_err());
        assert!(PublicKeyAnswer::new(pem(), Some(from), Some(to))
            .validate(Some(from + chrono::Duration::hours(1)))
            .is_ok());
        assert!(
            PublicKeyAnswer::parse(&pem()).is_err(),
            "the PEM alone is not the answer"
        );
    }
}

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

//! A creator's published schedule of signing public keys, and the rule for
//! choosing the key in force at a moment.
//!
//! Creators rotate their signing key, weekly in the case of the 51Degrees
//! cloud, so the key that is current when an identifier is checked is not the
//! key that signed it unless the check happens in the same week. The rule for
//! choosing is the one the cloud itself applies, being the latest key whose
//! start is at or before the moment asked about. Keys are generated in
//! batches, often many weeks ahead of the weeks they cover, so the moment key
//! material was generated says nothing about which key signed anything and is
//! not held here.

use chrono::{DateTime, Utc};

/// One signing public key together with the moment it came into force. The
/// key stays in force until the next key in the schedule starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatedPublicKey {
    /// The UTC moment from which this key signs.
    pub starts_at: DateTime<Utc>,
    /// The public key in PEM form.
    pub public_key_pem: String,
}

impl DatedPublicKey {
    /// A key that came into force at the moment.
    pub fn new(starts_at: DateTime<Utc>, public_key_pem: impl Into<String>) -> Self {
        DatedPublicKey {
            starts_at,
            public_key_pem: public_key_pem.into(),
        }
    }
}

/// A creator's published schedule of keys, from which the key in force at
/// any moment can be found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeySchedule {
    keys: Vec<DatedPublicKey>,
}

impl PublicKeySchedule {
    /// Holds the keys provided, which may arrive in any order. Where two
    /// keys share a start, the one supplied first wins, which is how the
    /// 51Degrees cloud settles it.
    pub fn new(keys: Vec<DatedPublicKey>) -> Self {
        let mut keys = keys;
        keys.sort_by_key(|key| key.starts_at);
        PublicKeySchedule { keys }
    }

    /// The keys held, oldest start first.
    pub fn keys(&self) -> &[DatedPublicKey] {
        &self.keys
    }

    /// The key that was in force at the moment, being the latest key whose
    /// start is at or before it, or `None` where the schedule begins after
    /// the moment.
    pub fn key_in_force(&self, at: DateTime<Utc>) -> Option<&DatedPublicKey> {
        let mut index = self.keys.iter().rposition(|key| key.starts_at <= at)?;
        while index > 0 && self.keys[index - 1].starts_at == self.keys[index].starts_at {
            index -= 1;
        }
        Some(&self.keys[index])
    }

    /// The earliest start in the schedule after the key's own, being the
    /// moment the key stops being in force, or `None` where the key is the
    /// last in the schedule and is in force until further notice.
    pub fn next_start_after(&self, key: &DatedPublicKey) -> Option<DateTime<Utc>> {
        self.keys
            .iter()
            .filter(|other| other.starts_at > key.starts_at)
            .map(|other| other.starts_at)
            .min()
    }

    /// The key in force now, which is what a creator serves for a request
    /// that names no date. It is not the last key of the schedule, because a
    /// schedule is published ahead of time and its last key has usually not
    /// started.
    pub fn current(&self) -> Option<&DatedPublicKey> {
        self.key_in_force(Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 8, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn chooses_the_latest_key_that_had_started() {
        let schedule = PublicKeySchedule::new(vec![
            DatedPublicKey::new(at(31), "third"),
            DatedPublicKey::new(at(17), "first"),
            DatedPublicKey::new(at(24), "second"),
        ]);
        assert_eq!(
            schedule.key_in_force(at(20)).unwrap().public_key_pem,
            "first"
        );
        assert_eq!(
            schedule.key_in_force(at(24)).unwrap().public_key_pem,
            "second"
        );
        assert_eq!(
            schedule.key_in_force(at(30)).unwrap().public_key_pem,
            "second"
        );
        assert!(schedule.key_in_force(at(10)).is_none());
        assert_eq!(
            schedule.keys()[0].public_key_pem,
            "first",
            "keys are held oldest first"
        );
    }

    #[test]
    fn knows_when_each_key_stops() {
        let schedule = PublicKeySchedule::new(vec![
            DatedPublicKey::new(at(17), "first"),
            DatedPublicKey::new(at(24), "second"),
        ]);
        assert_eq!(schedule.next_start_after(&schedule.keys()[0]), Some(at(24)));
        assert_eq!(schedule.next_start_after(&schedule.keys()[1]), None);
    }
}

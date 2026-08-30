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

//! Reading an OWID from bytes that came from outside.
//!
//! The buffer is walked by index and every read is checked against what is
//! left, so a malformed envelope is a comparison that fails rather than an
//! error raised deep inside a helper and caught somewhere else. That matters
//! because the data comes from outside, and whoever sends it chooses how
//! often this fails and how large each attempt is.
//!
//! This is the exact buffer contract. The envelope must end where the buffer
//! does, so a byte after the signature is refused. The crate reads no framed
//! stream, where an envelope is followed by more data, so nothing here has
//! to decide whether trailing bytes are rubbish or the next envelope.

use std::fmt;

use chrono::{DateTime, Duration, Utc};

use crate::io::{base_date, MAXIMUM_DOMAIN_LENGTH};
use crate::owid::Owid;
use crate::status::ParseStatus;
use crate::version::Version;
use crate::SIGNATURE_LENGTH;

/// What is known about a failure beyond the status that names it.
///
/// None of these carry any part of the input, so logging a parse failure
/// cannot log whatever an untrusted sender chose to put in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseDetail {
    /// Nothing is known beyond the status itself.
    None,
    /// The name of the field the data stopped inside.
    Field(&'static str),
    /// The version byte that this implementation does not support.
    Version(u8),
    /// The payload count the sender declared, and the count actually
    /// present, which is negative when the buffer holds fewer bytes after
    /// the length field than a signature needs.
    ByteCounts {
        /// The count read from the four byte payload length field.
        declared: u32,
        /// The bytes after the length field less the signature length.
        present: i64,
    },
    /// The number of bytes the read would have had to reserve.
    Capacity {
        /// The bytes the read would have had to reserve.
        required: u64,
    },
    /// The longest the domain field is allowed to be, in characters.
    MaximumDomainLength(usize),
}

impl fmt::Display for ParseDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseDetail::None => Ok(()),
            ParseDetail::Field(name) => write!(f, "stopped inside {name}"),
            ParseDetail::Version(v) => write!(f, "version '{v}'"),
            ParseDetail::ByteCounts { declared, present } => {
                write!(f, "declared '{declared}' with '{present}' present")
            }
            ParseDetail::Capacity { required } => {
                write!(f, "'{required}' bytes required")
            }
            ParseDetail::MaximumDomainLength(maximum) => {
                write!(
                    f,
                    "longer than the '{maximum}' character maximum, or not terminated"
                )
            }
        }
    }
}

/// Why bytes offered to this crate are not an OWID.
///
/// Malformed data arriving from outside is expected rather than
/// exceptional, so this is an ordinary value returned in the error half of
/// a [`Result`], carrying a [`ParseStatus`] a caller can branch on without
/// matching on message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    status: ParseStatus,
    detail: ParseDetail,
}

impl ParseError {
    pub(crate) fn new(status: ParseStatus, detail: ParseDetail) -> Self {
        ParseError { status, detail }
    }

    /// The specific reason the bytes are not an OWID.
    pub fn status(&self) -> ParseStatus {
        self.status
    }

    /// What is known about the failure beyond the status. Never any part
    /// of the input.
    pub fn detail(&self) -> ParseDetail {
        self.detail
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.detail {
            ParseDetail::None => write!(f, "{}", self.status),
            detail => write!(f, "{}: {}", self.status, detail),
        }
    }
}

impl std::error::Error for ParseError {}

/// Shorthand for a failure with no detail beyond its status.
fn fail<T>(status: ParseStatus) -> Result<T, ParseError> {
    Err(ParseError::new(status, ParseDetail::None))
}

/// Shorthand for a failure that knows something more.
fn fail_with<T>(status: ParseStatus, detail: ParseDetail) -> Result<T, ParseError> {
    Err(ParseError::new(status, detail))
}

/// Reads one complete OWID occupying the whole of the buffer.
pub(crate) fn parse_exact(buffer: &[u8]) -> Result<Owid, ParseError> {
    // An empty buffer is nothing to read rather than something that ran
    // out. Rust has no null to tell apart from it, so the two cases the
    // other implementations separate are one case here.
    if buffer.is_empty() {
        return fail(ParseStatus::MissingInput);
    }
    let total = buffer.len();

    // The version decides the width of the date field, so it is read
    // first. The empty marker, version zero, says an OWID is absent, and a
    // marker is not itself an OWID.
    let version = match Version::try_from(buffer[0]) {
        Ok(Version::Empty) | Err(_) => {
            return fail_with(
                ParseStatus::UnsupportedVersion,
                ParseDetail::Version(buffer[0]),
            )
        }
        Ok(version) => version,
    };
    let mut at = 1;

    let (domain, used) = read_domain(&buffer[at..])?;
    at += used;

    let date = read_date(&buffer[at..], version)?;
    at += date_length(version);

    if total - at < 4 {
        return fail_with(
            ParseStatus::UnexpectedEnd,
            ParseDetail::Field("the payload length"),
        );
    }
    let declared = u32::from_le_bytes([buffer[at], buffer[at + 1], buffer[at + 2], buffer[at + 3]]);
    at += 4;

    // The declaration is the sender's claim about a payload not yet read,
    // so it is compared with what is actually present before anything is
    // sized by it. The count is computed signed and wide, so a buffer with
    // fewer bytes left than a signature needs gives a negative number
    // rather than wrapping, and a negative number can never equal a
    // declaration.
    //
    // The disagreement is the finding even when the buffer also stopped
    // early. What a reader can say for certain is that the declared
    // payload cannot leave exactly the signature the version requires, and
    // that is true whichever way the bytes fall short.
    let present = (total - at) as i64 - SIGNATURE_LENGTH as i64;
    if present != i64::from(declared) {
        return fail_with(
            ParseStatus::ByteCountMismatch,
            ParseDetail::ByteCounts { declared, present },
        );
    }

    // The bytes are all here. Whether this build can hold them is a
    // separate question with a different answer, because the same envelope
    // may be readable on a machine with a wider pointer or more memory.
    let count = usize::try_from(declared).map_err(|_| {
        ParseError::new(
            ParseStatus::ImplementationCapacityExceeded,
            ParseDetail::Capacity {
                required: u64::from(declared),
            },
        )
    })?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(count).map_err(|_| {
        ParseError::new(
            ParseStatus::ImplementationCapacityExceeded,
            ParseDetail::Capacity {
                required: count as u64,
            },
        )
    })?;
    payload.extend_from_slice(&buffer[at..at + count]);
    at += count;

    let signature = buffer[at..at + SIGNATURE_LENGTH].to_vec();
    at += SIGNATURE_LENGTH;

    if at != total {
        // Unreachable while the count check above holds, and kept so that
        // a later change to that arithmetic cannot quietly start accepting
        // bytes after the envelope.
        return fail(ParseStatus::MalformedEnvelope);
    }

    Ok(Owid::from_parts(version, domain, date, payload, signature))
}

/// Reads the creator domain from the start of the bytes, returning it with
/// the number of bytes it occupied including its terminator.
///
/// The terminator is whatever the sender wrote, so the search for it stops
/// after [`MAXIMUM_DOMAIN_LENGTH`] characters rather than running on to the
/// end of the buffer. The work a hostile buffer can ask for here is
/// therefore fixed by that constant and not by the length of the input.
pub(crate) fn read_domain(bytes: &[u8]) -> Result<(String, usize), ParseError> {
    let window = bytes.len().min(MAXIMUM_DOMAIN_LENGTH + 1);
    let terminator = bytes[..window].iter().position(|&b| b == 0);
    let terminator = match terminator {
        Some(terminator) => terminator,
        // Either the buffer ended inside the domain, or the domain ran
        // past the maximum without terminating. The second is a domain
        // that cannot be valid rather than data that merely stopped, so
        // the two are reported differently.
        None if window > MAXIMUM_DOMAIN_LENGTH => {
            return fail_with(
                ParseStatus::InvalidDomainEncoding,
                ParseDetail::MaximumDomainLength(MAXIMUM_DOMAIN_LENGTH),
            )
        }
        None => {
            return fail_with(
                ParseStatus::UnexpectedEnd,
                ParseDetail::Field("the creator domain"),
            )
        }
    };
    match std::str::from_utf8(&bytes[..terminator]) {
        Ok(domain) => Ok((domain.to_owned(), terminator + 1)),
        Err(_) => fail_with(
            ParseStatus::InvalidDomainEncoding,
            ParseDetail::Field("the creator domain"),
        ),
    }
}

/// The width of the date field for the version.
pub(crate) fn date_length(version: Version) -> usize {
    match version {
        Version::Version1 => 2,
        _ => 4,
    }
}

/// Reads the date from the start of the bytes using the encoding the
/// version calls for.
pub(crate) fn read_date(bytes: &[u8], version: Version) -> Result<DateTime<Utc>, ParseError> {
    let width = date_length(version);
    if bytes.len() < width {
        return fail_with(ParseStatus::UnexpectedEnd, ParseDetail::Field("the date"));
    }
    match version {
        // Version 1 counted whole hours in two big endian bytes.
        Version::Version1 => {
            let hours = i64::from(bytes[0]) << 8 | i64::from(bytes[1]);
            Ok(base_date() + Duration::hours(hours))
        }
        // Every later version counts minutes in four little endian bytes.
        // The widest value a sender can write is inside what a date can
        // hold, so the addition cannot overflow.
        _ => {
            let minutes = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok(base_date() + Duration::minutes(i64::from(minutes)))
        }
    }
}

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
//! There are two ways to read. The whole buffer read requires the envelope
//! to end where the buffer does, so a byte after the signature is refused,
//! because in a buffer holding one OWID nothing else could own that byte.
//! The framed read requires only that the declared payload and the
//! signature are present, and says nothing about what follows, because what
//! follows may be the next envelope rather than rubbish.
//!
//! They differ in two answers, both about the bytes after the length field.
//! A whole buffer that declares a payload not matching what is present is a
//! [`ParseStatus::ByteCountMismatch`], because all the bytes are there by
//! definition and the declaration disagrees with them. A frame whose
//! declared payload runs past what was supplied is a
//! [`ParseStatus::UnexpectedEnd`], because the data stopped early, and a
//! caller reading from a source still arriving can wait for more bytes on
//! one answer and has to give up on the other.
//!
//! The other difference is the one byte marker standing for a node that is
//! not there. A frame may hold one, so the framed read steps over it and
//! carries on, while a whole buffer holding one is not an OWID at all.

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
    /// The name of the field the data stopped inside.
    Field(&'static str),
    /// The version byte that this implementation does not support. Named
    /// for the byte rather than for the version, because it is a number
    /// that did not match a [`crate::Version`] rather than one that did.
    VersionByte(u8),
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
            ParseDetail::Field(name) => write!(f, "stopped inside {name}"),
            ParseDetail::VersionByte(v) => write!(f, "version '{v}'"),
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
    detail: Option<ParseDetail>,
}

impl ParseError {
    pub(crate) fn new(status: ParseStatus, detail: Option<ParseDetail>) -> Self {
        ParseError { status, detail }
    }

    /// The specific reason the bytes are not an OWID.
    pub fn status(&self) -> ParseStatus {
        self.status
    }

    /// What is known about the failure beyond the status, where anything
    /// is. Never any part of the input.
    pub fn detail(&self) -> Option<ParseDetail> {
        self.detail
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.detail {
            None => write!(f, "{}", self.status),
            Some(detail) => write!(f, "{}: {}", self.status, detail),
        }
    }
}

impl std::error::Error for ParseError {}

/// Shorthand for a failure with no detail beyond its status.
fn fail<T>(status: ParseStatus) -> Result<T, ParseError> {
    Err(ParseError::new(status, None))
}

/// Shorthand for a failure that knows something more.
fn fail_with<T>(status: ParseStatus, detail: ParseDetail) -> Result<T, ParseError> {
    Err(ParseError::new(status, Some(detail)))
}

/// How much of the buffer the envelope has to account for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Extent {
    /// The envelope is the whole buffer and must end where it does.
    WholeBuffer,
    /// The envelope is at the front of the buffer and whatever follows
    /// belongs to whoever is reading the next one.
    Prefix,
}

/// Reads one complete OWID occupying the whole of the buffer.
pub(crate) fn parse_exact(buffer: &[u8]) -> Result<Owid, ParseError> {
    let (owid, used) = parse_one(buffer, Extent::WholeBuffer)?;
    debug_assert_eq!(used, buffer.len(), "the whole buffer read consumes it all");
    Ok(owid)
}

/// Reads one complete OWID from the front of the buffer, returning it with
/// the bytes that follow it.
///
/// Nothing is consumed when this fails, because the buffer is borrowed and
/// the bytes that follow are handed back only on success, so a caller can
/// never be left part way through an envelope it could not read.
pub(crate) fn parse_prefix(buffer: &[u8]) -> Result<(Option<Owid>, &[u8]), ParseError> {
    if buffer.is_empty() {
        return fail(ParseStatus::MissingInput);
    }
    // A frame may say that the node it holds is not there. The marker is
    // one byte and carries no signature, so there is no OWID to hand back,
    // and stepping over it is what lets a caller reach the next frame.
    if buffer[0] == Version::Empty.as_byte() {
        return Ok((None, &buffer[1..]));
    }
    let (owid, used) = parse_one(buffer, Extent::Prefix)?;
    Ok((Some(owid), &buffer[used..]))
}

/// Reads one envelope from the front of the buffer, returning it with the
/// number of bytes it occupied.
fn parse_one(buffer: &[u8], extent: Extent) -> Result<(Owid, usize), ParseError> {
    // An empty buffer is nothing to read rather than something that ran
    // out. Rust has no null to tell apart from it, so the two cases the
    // other implementations separate are one case here.
    if buffer.is_empty() {
        return fail(ParseStatus::MissingInput);
    }
    let total = buffer.len();

    // The version decides the width of the date field, so it is read
    // first. Version zero is the marker saying a node is not there, which
    // is a meaningful thing to find and not an unsupported version, but it
    // is not an OWID either, so nothing is handed back for it.
    let version = match Version::try_from(buffer[0]) {
        Ok(Version::Empty) => return fail(ParseStatus::AbsentNode),
        Err(_) => {
            return fail_with(
                ParseStatus::UnsupportedVersion,
                ParseDetail::VersionByte(buffer[0]),
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
    // This comparison is where the two reads differ, and so are their
    // answers.
    //
    // A whole buffer holds one OWID and every byte of it, so a count that
    // does not match exactly is a declaration disagreeing with data that is
    // all present, which is a mismatch whichever way the bytes fall short,
    // a byte after the signature included.
    //
    // A frame may be part of a source still arriving, so a declared payload
    // running past what was supplied is data that stopped early rather than
    // a disagreement, and the difference matters to a caller deciding
    // whether to wait for more bytes or give up. Bytes beyond the payload
    // and signature are not judged at all, because they belong to whoever
    // reads the next frame.
    let present = (total - at) as i64 - SIGNATURE_LENGTH as i64;
    let counts = ParseDetail::ByteCounts { declared, present };
    match extent {
        Extent::WholeBuffer if present != i64::from(declared) => {
            return fail_with(ParseStatus::ByteCountMismatch, counts)
        }
        Extent::Prefix if present < i64::from(declared) => {
            return fail_with(ParseStatus::UnexpectedEnd, counts)
        }
        _ => {}
    }

    // The bytes are all here. Whether this build can hold them is a
    // separate question with a different answer, because the same envelope
    // may be readable on a machine with a wider pointer or more memory.
    let count = usize::try_from(declared).map_err(|_| {
        ParseError::new(
            ParseStatus::ImplementationCapacityExceeded,
            Some(ParseDetail::Capacity {
                required: u64::from(declared),
            }),
        )
    })?;
    let mut payload = Vec::new();
    payload.try_reserve_exact(count).map_err(|_| {
        ParseError::new(
            ParseStatus::ImplementationCapacityExceeded,
            Some(ParseDetail::Capacity {
                required: count as u64,
            }),
        )
    })?;
    payload.extend_from_slice(&buffer[at..at + count]);
    at += count;

    let signature = buffer[at..at + SIGNATURE_LENGTH].to_vec();
    at += SIGNATURE_LENGTH;

    if extent == Extent::WholeBuffer && at != total {
        // Unreachable while the count check above holds, and kept so that
        // a later change to that arithmetic cannot quietly start accepting
        // bytes after the envelope. The framed read is not held to this,
        // because bytes after the envelope are the point of it.
        return fail(ParseStatus::MalformedEnvelope);
    }

    Ok((
        Owid::from_parts(version, domain, date, payload, signature),
        at,
    ))
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

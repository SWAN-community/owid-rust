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

//! Low level read and write helpers for the OWID binary format. The format
//! uses little endian unsigned 32 bit integers, null terminated strings, and
//! a fixed 64 byte signature.

use chrono::{DateTime, Duration, Utc};

use crate::error::{Error, Result};
use crate::version::Version;
use crate::SIGNATURE_LENGTH;

/// The longest creator domain an envelope may carry, counted in
/// characters of the text form. RFC 1035 section 2.3.4, "Size limits",
/// says that "the total length of a domain name (i.e., label octets and
/// label length octets) is restricted to 255 octets or less", and that
/// "labels must be 63 characters or less". Those 255 octets are the wire
/// format, which puts a length octet in front of every label and a zero
/// octet at the end for the root. An OWID stores the presentation form
/// instead, the text `example.com`, which writes a dot in place of each
/// of those length octets except the first, because nothing precedes the
/// first label, and writes nothing at all for the root. Two of the 255
/// octets therefore have no text counterpart, so the same published
/// limit is two characters fewer here. The OWID specification makes the
/// limit binding on a creator as well as on a consumer, so it bounds the
/// write in [`write_domain`] and in [`crate::Creator::new`] as well as
/// the read in [`Reader::read_domain`].
pub(crate) const MAXIMUM_DOMAIN_LENGTH: usize = 253;

/// The base date for OWIDs. The date and time information is stored in hours
/// or minutes after this date.
pub(crate) fn base_date() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_577_836_800, 0)
        .expect("should construct 2020-01-01T00:00:00Z")
}

/// Sequential reader over a byte buffer.
pub(crate) struct Reader<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buffer: &'a [u8]) -> Self {
        Reader {
            buffer,
            position: 0,
        }
    }

    pub(crate) fn read_byte(&mut self) -> Result<u8> {
        let value = *self
            .buffer
            .get(self.position)
            .ok_or(Error::UnexpectedEndOfBuffer)?;
        self.position += 1;
        Ok(value)
    }

    fn read_bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error::UnexpectedEndOfBuffer)?;
        let value = self
            .buffer
            .get(self.position..end)
            .ok_or(Error::UnexpectedEndOfBuffer)?;
        self.position = end;
        Ok(value)
    }

    /// Reads the creator domain, which is stored as text followed by a
    /// null terminator. The terminator is whatever the sender wrote, so
    /// the search for it stops after [`MAXIMUM_DOMAIN_LENGTH`] characters
    /// rather than running on to the end of the buffer. A buffer whose
    /// domain field carries no terminator within that many characters is
    /// refused with [`Error::DomainTooLong`] and the rest of the buffer is
    /// never touched, so the work a hostile buffer can ask for here is
    /// fixed by the constant and not by the length of the input. A buffer
    /// that simply runs out before a terminator is still
    /// [`Error::UnexpectedEndOfBuffer`], as it was before the bound was
    /// added on 30 August 2026, which the tests in
    /// `tests/payload_length.rs` hold the parser to.
    pub(crate) fn read_domain(&mut self) -> Result<String> {
        let remaining = &self.buffer[self.position..];
        let window = remaining.len().min(MAXIMUM_DOMAIN_LENGTH + 1);
        // A window wide enough to hold the terminator of the longest
        // domain allowed, with no terminator in it, means the domain is
        // too long. A narrower one means the buffer ran out first.
        let missing = if window > MAXIMUM_DOMAIN_LENGTH {
            Error::DomainTooLong
        } else {
            Error::UnexpectedEndOfBuffer
        };
        let terminator = remaining[..window]
            .iter()
            .position(|&b| b == 0)
            .ok_or(missing)?;
        let value = String::from_utf8(remaining[..terminator].to_vec())
            .map_err(|_| Error::InvalidDomainEncoding)?;
        self.position += terminator + 1;
        Ok(value)
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads the payload, which is prefixed with its length as an unsigned
    /// 32 bit integer and is the last variable length field of an OWID,
    /// followed by the signature and nothing else. The length is whatever
    /// the sender declared, so it is checked against the bytes present
    /// before anything is sized by it. The declared length must equal the
    /// bytes remaining less the signature length, and any other length,
    /// short or long, is refused here with
    /// [`Error::PayloadLengthMismatch`]. A byte after the signature fails
    /// this check as well. Until 28 August 2026 the parser only checked
    /// that the declared count fitted in the buffer, so trailing bytes
    /// were ignored, and it copied the payload from a slice, so a huge
    /// declared count never sized an allocation, which the tests in
    /// `tests/payload_length.rs` now hold the parser to.
    pub(crate) fn read_payload(&mut self) -> Result<Vec<u8>> {
        let declared = self.read_u32()?;
        let present = self.buffer.len() - self.position;
        let count = usize::try_from(declared).ok();
        let expected = count.and_then(|c| c.checked_add(SIGNATURE_LENGTH));
        match (count, expected) {
            (Some(count), Some(expected)) if expected == present => {
                let bytes = self.read_bytes(count)?;
                let mut payload = Vec::new();
                payload
                    .try_reserve_exact(count)
                    .map_err(|_| Error::ImplementationCapacityExceeded { required: count })?;
                payload.extend_from_slice(bytes);
                Ok(payload)
            }
            _ => Err(Error::PayloadLengthMismatch { declared, present }),
        }
    }

    /// Reads the fixed length signature. After [`Reader::read_payload`]
    /// exactly this many bytes remain, so the read cannot fall short.
    pub(crate) fn read_signature(&mut self) -> Result<Vec<u8>> {
        Ok(self.read_bytes(SIGNATURE_LENGTH)?.to_vec())
    }

    /// Reads the date using the encoding associated with the version.
    pub(crate) fn read_date(&mut self, version: Version) -> Result<DateTime<Utc>> {
        match version {
            Version::Version1 => {
                let high = self.read_byte()?;
                let low = self.read_byte()?;
                let hours = i64::from(high) << 8 | i64::from(low);
                Ok(base_date() + Duration::hours(hours))
            }
            Version::Version2 | Version::Version3 => {
                let minutes = self.read_u32()?;
                Ok(base_date() + Duration::minutes(i64::from(minutes)))
            }
            other => Err(Error::UnsupportedVersion(other.as_byte())),
        }
    }
}

pub(crate) fn write_byte(buffer: &mut Vec<u8>, value: u8) {
    buffer.push(value);
}

/// Writes the creator domain followed by the null terminator. The domain
/// must not contain a null character as that would conflict with the
/// terminator, and must not be longer than [`MAXIMUM_DOMAIN_LENGTH`],
/// which [`Reader::read_domain`] refuses on the way back in, so writing a
/// longer one would produce an OWID this crate could not read.
///
/// This is the second of the two places the write bound is applied, the
/// first being [`crate::Creator::new`]. The bound is repeated here because
/// [`crate::Owid::domain`] is a public field, so a domain can reach the
/// serializer without passing through a creator. What is counted is the
/// bytes the value occupies once written, which is what the read then
/// measures. The method is named for the domain rather than for strings
/// because the domain is its only caller, matching
/// [`Reader::read_domain`].
pub(crate) fn write_domain(buffer: &mut Vec<u8>, value: &str) -> Result<()> {
    if value.bytes().any(|b| b == 0) {
        return Err(Error::InvalidDomain(value.to_owned()));
    }
    if value.len() > MAXIMUM_DOMAIN_LENGTH {
        return Err(Error::DomainTooLong);
    }
    buffer.extend_from_slice(value.as_bytes());
    buffer.push(0);
    Ok(())
}

pub(crate) fn write_u32(buffer: &mut Vec<u8>, value: u32) {
    buffer.extend_from_slice(&value.to_le_bytes());
}

/// Writes a byte array prefixed with its length as an unsigned 32 bit
/// integer.
pub(crate) fn write_byte_array(buffer: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length = u32::try_from(value.len()).map_err(|_| Error::PayloadTooLarge(value.len()))?;
    write_u32(buffer, length);
    buffer.extend_from_slice(value);
    Ok(())
}

/// Writes the fixed length signature, validating the length.
pub(crate) fn write_signature(buffer: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    if value.len() != SIGNATURE_LENGTH {
        return Err(Error::InvalidSignatureLength(value.len()));
    }
    buffer.extend_from_slice(value);
    Ok(())
}

/// Writes the date using the encoding associated with the version.
pub(crate) fn write_date(
    buffer: &mut Vec<u8>,
    date: &DateTime<Utc>,
    version: Version,
) -> Result<()> {
    match version {
        Version::Version1 => {
            let hours = (*date - base_date()).num_hours();
            let hours = u16::try_from(hours).map_err(|_| Error::DateOutOfRange)?;
            buffer.push((hours >> 8) as u8);
            buffer.push((hours & 0x00FF) as u8);
            Ok(())
        }
        Version::Version2 | Version::Version3 => {
            let minutes = (*date - base_date()).num_minutes();
            let minutes = u32::try_from(minutes).map_err(|_| Error::DateOutOfRange)?;
            write_u32(buffer, minutes);
            Ok(())
        }
        other => Err(Error::UnsupportedVersion(other.as_byte())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Port of the Go TestIoTime test. A date written and read with the
    /// version 2 encoding must keep the same year, month, and day.
    #[test]
    fn date_roundtrip_version_2() {
        let date = Utc::now();
        let mut buffer = Vec::new();
        write_date(&mut buffer, &date, Version::Version2).expect("should write the date");
        let mut reader = Reader::new(&buffer);
        let result = reader
            .read_date(Version::Version2)
            .expect("should read the date");
        assert_eq!(
            result.date_naive(),
            date.date_naive(),
            "should keep the same calendar date"
        );
        assert_eq!(
            (result - base_date()).num_minutes(),
            (date - base_date()).num_minutes(),
            "should keep the same minute count"
        );
    }

    /// A date written and read with the version 1 encoding must keep hour
    /// granularity.
    #[test]
    fn date_roundtrip_version_1() {
        let date = base_date() + Duration::hours(12_345);
        let mut buffer = Vec::new();
        write_date(&mut buffer, &date, Version::Version1).expect("should write the date");
        assert_eq!(buffer.len(), 2, "should use two bytes for version 1");
        let mut reader = Reader::new(&buffer);
        let result = reader
            .read_date(Version::Version1)
            .expect("should read the date");
        assert_eq!(result, date, "should keep hour granularity");
    }

    /// Dates before the base date can not be encoded.
    #[test]
    fn date_before_base_errors() {
        let date = base_date() - Duration::minutes(1);
        let mut buffer = Vec::new();
        let result = write_date(&mut buffer, &date, Version::Version3);
        assert!(
            matches!(result, Err(Error::DateOutOfRange)),
            "should reject dates before the base date"
        );
    }

    /// Strings are written with a null terminator and read back without it.
    #[test]
    fn string_roundtrip() {
        let mut buffer = Vec::new();
        write_domain(&mut buffer, "example.com").expect("should write the domain");
        assert_eq!(buffer.last(), Some(&0), "should be null terminated");
        let mut reader = Reader::new(&buffer);
        let result = reader.read_domain().expect("should read string");
        assert_eq!(result, "example.com", "should match the original string");
    }

    /// A domain of exactly the maximum length is written and read back
    /// unchanged, so the write bound refuses nothing the read accepts.
    /// The maximum is read from the constant rather than spelled out,
    /// because what is checked is that the two halves stop in the same
    /// place.
    #[test]
    fn write_domain_accepts_maximum_length() {
        let value = "a".repeat(MAXIMUM_DOMAIN_LENGTH);
        let mut buffer = Vec::new();
        write_domain(&mut buffer, &value).expect("should write the longest domain");
        let mut reader = Reader::new(&buffer);
        let result = reader.read_domain().expect("should read it back");
        assert_eq!(result, value, "should round trip the longest domain");
    }

    /// One character more is refused, and nothing is appended, so a caller
    /// filling a buffer is not left with part of a domain in it.
    #[test]
    fn write_domain_over_maximum_is_refused() {
        let value = "a".repeat(MAXIMUM_DOMAIN_LENGTH + 1);
        let mut buffer = Vec::new();
        let error = write_domain(&mut buffer, &value).expect_err("should refuse");
        assert!(
            matches!(error, Error::DomainTooLong),
            "a domain over the maximum should be refused, got {error:?}"
        );
        assert!(buffer.is_empty(), "should write nothing when refusing");
    }

    /// Unsigned 32 bit integers use little endian byte order.
    #[test]
    fn u32_little_endian() {
        let mut buffer = Vec::new();
        write_u32(&mut buffer, 0x0A24_2B01);
        assert_eq!(
            buffer,
            vec![0x01, 0x2B, 0x24, 0x0A],
            "should be little endian"
        );
        let mut reader = Reader::new(&buffer);
        assert_eq!(
            reader.read_u32().expect("should read u32"),
            0x0A24_2B01,
            "should round trip"
        );
    }
}

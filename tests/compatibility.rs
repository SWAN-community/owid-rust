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

//! Cross language compatibility tests. The fixtures are the base 64 encoded
//! OWIDs used by the JavaScript implementation test suite, so these tests
//! prove that the Rust implementation reads the same wire format as the
//! other languages.

use base64::engine::general_purpose::STANDARD;
use base64::engine::Engine as _;
use chrono::{DateTime, Duration, Utc};
use owid::{Owid, Version};

/// OWID created by the demo creator domain. Contains a payload of 341 bytes
/// which itself holds other serialized OWIDs.
const TEST_CREATOR_OWID: &str = concat!(
    "AjUxZGIudWsAKyQKAFUBAAABAWhlYWRpbmcAcG9wLXVwLnN3YW4tZGVtby51awAQAAAA27eO",
    "AAPSTXmKZT79iWgRagI1MWRhLnVrACskCgAQAAAAs1WelonmS0KoK6uiN3rz1rAxJHj2rNKv",
    "V/9OMOyFlWHY/tbwpdVupNG62p3pCWCuzgV2YMEth3coZhFSZHXJ1mO/U/bkHhGCSG/BStI/",
    "fJcCNTFkYi51awArJAoAFAAAAO/c7j2xwwF8GN4hOXBIb/auLhy7mftegVZqvbepqw8nVf8B",
    "yI94w9I/XLNwf5kAFpFeSeo8kwRhXqUyUuWT7FYIi4DnOP9zyTaAY8xgMh77oUjL/QJjbXAu",
    "c3dhbi1kZW1vLnVrACskCgACAAAAb25Lyrbl9PDGs6VAMqgozsfxCqsVWX6pf2JyFim3zg6l",
    "LivRDqpCD921elvxdn85/vK0msyTOMjE8buKAza/H2zBAEqEMbMuIoZL8Ji4m4ScYkpQvD3K",
    "jsLbqI5c7+Ra/Ju43vBMp2st7QLHD4sxwPugeSBEgQRkevAm0H1a3jekMEA"
);

/// OWID created by a supplier that was signed together with another OWID.
const TEST_SUPPLIER_OWID: &str = concat!(
    "AnBvcC11cC5zd2FuLWRlbW8udWsAKyQKAAIAAAABA6Ljm9cxZfnmwRMjv4MQ0PrAjf8y29Ru",
    "0sjZG5R+mkjBtQD9J02xZQIk5czsKJzOl6IkOPvbPSGakxyq0HPLX+w"
);

/// OWID from a bad actor whose signature does not verify.
const TEST_BAD_OWID: &str = concat!(
    "AmJhZHNzcC5zd2FuLWRlbW8udWsAKyQKAAIAAAABAxu+OOtismihze3LlcNuvT2WXNTGSio",
    "gw36t85HLwL6YdV4i9kYDCdsP54RS8on/roKKASyh19TpcUQxkIRALFk"
);

/// The date shared by all three fixtures as minutes after the base date.
const FIXTURE_MINUTES: i64 = 664_619;

fn base_date() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_577_836_800, 0)
        .expect("should construct 2020-01-01T00:00:00Z")
}

fn fixture_date() -> DateTime<Utc> {
    base_date() + Duration::minutes(FIXTURE_MINUTES)
}

/// The creator fixture from the JavaScript test suite decodes to the
/// expected field values.
#[test]
fn creator_fixture_fields() {
    let owid = Owid::from_base64(TEST_CREATOR_OWID).expect("should parse the creator fixture");
    assert_eq!(owid.version, Version::Version2, "version should be 2");
    assert_eq!(owid.domain, "51db.uk", "domain should match");
    assert_eq!(
        owid.date,
        fixture_date(),
        "date should be 2021-04-06 12:59Z"
    );
    assert_eq!(owid.payload.len(), 341, "payload should be 341 bytes");
    assert_eq!(owid.signature.len(), 64, "signature should be 64 bytes");
    assert_eq!(owid.signature[0], 74, "first signature byte should match");
    assert_eq!(owid.signature[63], 64, "last signature byte should match");
}

/// The supplier fixture decodes to the expected field values, including the
/// exact payload accessor outputs.
#[test]
fn supplier_fixture_fields() {
    let owid = Owid::from_base64(TEST_SUPPLIER_OWID).expect("should parse the supplier fixture");
    assert_eq!(owid.version, Version::Version2, "version should be 2");
    assert_eq!(owid.domain, "pop-up.swan-demo.uk", "domain should match");
    assert_eq!(
        owid.date,
        fixture_date(),
        "date should be 2021-04-06 12:59Z"
    );
    assert_eq!(
        owid.payload,
        vec![0x01, 0x03],
        "payload should be 0x01 0x03"
    );
    assert_eq!(
        owid.payload_as_base64(),
        "AQM=",
        "payload as base 64 should match the JavaScript value"
    );
    assert_eq!(
        owid.payload_as_printable(),
        "0103",
        "payload as printable should be zero padded hexadecimal"
    );
    assert_eq!(owid.signature.len(), 64, "signature should be 64 bytes");
}

/// The bad actor fixture still parses. Verification failure is a crypto
/// concern, not a parsing concern.
#[test]
fn bad_fixture_parses() {
    let owid = Owid::from_base64(TEST_BAD_OWID).expect("should parse the bad fixture");
    assert_eq!(owid.domain, "badssp.swan-demo.uk", "domain should match");
    assert_eq!(
        owid.payload,
        vec![0x01, 0x03],
        "payload should be 0x01 0x03"
    );
}

/// Parsing a fixture and serializing it again must produce the identical
/// bytes, proving the writer matches the other implementations.
#[test]
fn fixtures_roundtrip_byte_exact() {
    for fixture in [TEST_CREATOR_OWID, TEST_SUPPLIER_OWID, TEST_BAD_OWID] {
        let original = decode_unpadded(fixture);
        let owid = Owid::from_byte_array(&original).expect("should parse the fixture");
        let written = owid.as_byte_array().expect("should serialize");
        assert_eq!(written, original, "bytes should round trip exactly");
    }
}

/// The data used to verify a supplier OWID signed together with another
/// OWID is the supplier fields without the signature followed by the
/// complete bytes of the other. This mirrors the data construction in the
/// JavaScript verify method and the .NET and Go data for crypto functions.
#[test]
fn data_for_crypto_layout() {
    let creator_bytes = decode_unpadded(TEST_CREATOR_OWID);
    let supplier_bytes = decode_unpadded(TEST_SUPPLIER_OWID);
    let creator = Owid::from_byte_array(&creator_bytes).expect("should parse the creator");
    let supplier = Owid::from_byte_array(&supplier_bytes).expect("should parse the supplier");

    // The supplier crypto data must start with the supplier bytes without
    // the 64 byte signature and end with the complete creator bytes.
    let data = supplier_verification_data(&supplier, &creator);
    let no_signature_length = supplier_bytes.len() - 64;
    assert_eq!(
        &data[..no_signature_length],
        &supplier_bytes[..no_signature_length],
        "data should start with the supplier fields without the signature"
    );
    assert_eq!(
        &data[no_signature_length..],
        &creator_bytes[..],
        "data should end with the complete creator bytes"
    );
}

/// Builds the same byte sequence that verification uses by serializing the
/// supplier without its signature followed by the complete creator.
fn supplier_verification_data(supplier: &Owid, creator: &Owid) -> Vec<u8> {
    let mut unsigned = supplier.clone();
    unsigned.signature = Vec::new();
    // Serialize the unsigned form by removing the empty signature error
    // path. The public API serializes complete OWIDs only, so rebuild from
    // the parts in wire order.
    let mut data = Vec::new();
    data.push(unsigned.version.as_byte());
    data.extend_from_slice(unsigned.domain.as_bytes());
    data.push(0);
    let minutes = (unsigned.date - base_date()).num_minutes() as u32;
    data.extend_from_slice(&minutes.to_le_bytes());
    data.extend_from_slice(&(unsigned.payload.len() as u32).to_le_bytes());
    data.extend_from_slice(&unsigned.payload);
    data.extend_from_slice(
        &creator
            .as_byte_array()
            .expect("should serialize the creator"),
    );
    data
}

/// Decodes base 64 that may have had its padding removed, as the
/// JavaScript fixtures have.
fn decode_unpadded(value: &str) -> Vec<u8> {
    let padding = (4 - value.len() % 4) % 4;
    let padded = format!("{}{}", value, "=".repeat(padding));
    STANDARD.decode(padded).expect("should decode the fixture")
}

/// A version 1 buffer with a known two byte big endian hour count reads to
/// the expected date. Mirrors the .NET version 1 date tests. Note the Go
/// implementation interpreted these two bytes as days rather than hours.
/// This implementation follows the .NET reference.
#[test]
fn version_1_date_read_from_buffer() {
    // 9460 hours is 0x24F4.
    let mut buffer = vec![1u8];
    buffer.extend_from_slice(b"test.com\0");
    buffer.extend_from_slice(&[0x24, 0xF4]);
    buffer.extend_from_slice(&0u32.to_le_bytes());
    buffer.extend_from_slice(&[0u8; 64]);

    let owid = Owid::from_byte_array(&buffer).expect("should parse version 1");
    assert_eq!(owid.version, Version::Version1, "version should be 1");
    assert_eq!(
        owid.date,
        base_date() + Duration::hours(9460),
        "date should be the base date plus 9460 hours"
    );

    let written = owid.as_byte_array().expect("should serialize");
    assert_eq!(written, buffer, "version 1 bytes should round trip exactly");
}

/// A version 2 buffer with a known four byte little endian minute count
/// reads to the expected date.
#[test]
fn version_2_date_read_from_buffer() {
    let mut buffer = vec![2u8];
    buffer.extend_from_slice(b"test.com\0");
    buffer.extend_from_slice(&(FIXTURE_MINUTES as u32).to_le_bytes());
    buffer.extend_from_slice(&0u32.to_le_bytes());
    buffer.extend_from_slice(&[0u8; 64]);

    let owid = Owid::from_byte_array(&buffer).expect("should parse version 2");
    assert_eq!(owid.version, Version::Version2, "version should be 2");
    assert_eq!(owid.date, fixture_date(), "date should match the minutes");
}

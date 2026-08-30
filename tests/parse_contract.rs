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

//! The contract a read of an OWID answers to, which is the same contract in
//! every language that implements OWID.
//!
//! A read always reports three things, being whether it worked, the OWID
//! only when it did, and a named reason either way. This file holds the
//! cases of the shared status matrix, and the cases that prove an OWID can
//! not exist in an unsigned state.
//!
//! The two routes to an OWID are checked here as a pair. Everything a
//! library user could do before this crate closed construction they can
//! still do, by creating through a [`Creator`] rather than by assembling
//! one and signing it afterwards.
//!
//! Rust refuses at compile time what other languages have to refuse at run
//! time, so the cases about construction and mutation are documentation
//! tests marked `compile_fail` on [`owid::Owid`] rather than tests here.
//! They are compiled by `cargo test`, and they fail if the fields or the
//! constructor ever become public again.

use owid::{Creator, Crypto, Owid, ParseDetail, ParseStatus, SignatureStatus, SIGNATURE_LENGTH};

const DOMAIN: &str = "test.com";

fn creator() -> Creator {
    Creator::new(DOMAIN, Crypto::new()).expect("should create the creator")
}

/// A version 3 envelope built by hand, so a test can make the declared
/// count and the bytes present disagree, or stop the buffer part way
/// through a field.
fn envelope(declared: u32, payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = vec![3u8];
    bytes.extend_from_slice(DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(&declared.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(signature);
    bytes
}

/// Asserts everything a failed read must report, being that it did not
/// work, that no OWID came back, and that the reason is the one expected.
/// Nothing here can panic on the crate's behalf, so reaching the assertions
/// at all is the evidence that the read answered rather than aborting.
fn assert_refused(result: Result<Owid, owid::ParseError>, expected: ParseStatus) {
    assert!(result.is_err(), "the read should not report success");
    assert_eq!(
        ParseStatus::of(&result),
        expected,
        "the read should report the reason"
    );
    assert!(
        result.err().is_some(),
        "a failed read should hand back no OWID"
    );
}

/// A successful read reports all three facts, being that it worked, the
/// OWID, and the status `Parsed`.
#[test]
fn success_reports_all_three_facts() {
    let original = creator().create("Hello World").expect("should create");
    let encoded = original.as_base64().expect("should encode");

    let result = Owid::from_base64(&encoded);

    assert!(result.is_ok(), "the read should report success");
    assert_eq!(
        ParseStatus::of(&result),
        ParseStatus::Parsed,
        "success should be named Parsed"
    );
    let owid = result.expect("checked above");
    assert_eq!(owid.payload(), original.payload(), "should carry the OWID");
}

/// A payload of nothing at all is valid. Having nothing to say is allowed.
#[test]
fn empty_payload_parses() {
    let original = creator().create(Vec::new()).expect("should create");
    let encoded = original.as_base64().expect("should encode");

    let owid = Owid::from_base64(&encoded).expect("an empty payload should parse");

    assert!(owid.payload().is_empty(), "the payload should be empty");
    assert_eq!(
        owid.signature().len(),
        SIGNATURE_LENGTH,
        "an empty payload is still signed"
    );
}

/// A payload of a megabyte parses. The limit on the size of a payload is
/// the wire format's, and how much an application accepts is that
/// application's policy rather than this crate's.
#[test]
fn one_megabyte_payload_parses() {
    let payload = vec![0x5A; 1024 * 1024];
    let original = creator().create(payload.clone()).expect("should create");
    let encoded = original.as_base64().expect("should encode");

    let owid = Owid::from_base64(&encoded).expect("a megabyte payload should parse");

    assert_eq!(owid.payload(), payload, "the payload should round trip");
}

/// Nothing to read is nothing to read, whether it arrives as an empty
/// string or as an empty buffer. Rust has no null to tell apart from
/// either.
#[test]
fn absent_input_is_missing_input() {
    assert_refused(Owid::from_base64(""), ParseStatus::MissingInput);
    assert_refused(Owid::from_byte_array(&[]), ParseStatus::MissingInput);
}

/// A string that is not base 64 is reported, not raised.
#[test]
fn invalid_base64_is_reported() {
    assert_refused(
        Owid::from_base64("This is not valid Base64!@#$"),
        ParseStatus::InvalidBase64,
    );
}

/// A version byte this implementation does not know is refused, and the
/// detail names the byte so a log says which version arrived.
#[test]
fn unknown_version_is_reported() {
    let result = Owid::from_byte_array(&[9, 9, 9]);
    assert_refused(result, ParseStatus::UnsupportedVersion);

    let error = Owid::from_byte_array(&[9, 9, 9]).expect_err("should refuse");
    assert_eq!(
        error.detail(),
        Some(ParseDetail::VersionByte(9)),
        "the detail should name the version byte"
    );
}

/// One byte after a complete envelope is a declaration that disagrees with
/// the bytes present, because the declared payload no longer leaves exactly
/// the signature at the end.
#[test]
fn trailing_byte_is_a_byte_count_mismatch() {
    let payload = b"Hello World";
    let mut bytes = envelope(payload.len() as u32, payload, &[0x99; SIGNATURE_LENGTH]);
    bytes.push(0);

    assert_refused(
        Owid::from_byte_array(&bytes),
        ParseStatus::ByteCountMismatch,
    );
}

/// Data that stops inside a field, before the declared payload count has
/// even been read, is an unexpected end. This is the case
/// `ByteCountMismatch` is not, and each field is checked separately so that
/// a later change cannot quietly collapse the two.
#[test]
fn stopping_inside_the_envelope_is_an_unexpected_end() {
    let complete = envelope(0, &[], &[0x99; SIGNATURE_LENGTH]);
    let header = 1 + DOMAIN.len() + 1;

    // Inside the domain, which has not reached its terminator.
    assert_refused(
        Owid::from_byte_array(&complete[..header - 2]),
        ParseStatus::UnexpectedEnd,
    );
    // After the domain, with the date incomplete.
    assert_refused(
        Owid::from_byte_array(&complete[..header + 2]),
        ParseStatus::UnexpectedEnd,
    );
    // After the date, with the payload length field incomplete.
    assert_refused(
        Owid::from_byte_array(&complete[..header + 4 + 3]),
        ParseStatus::UnexpectedEnd,
    );
}

/// The domain bytes must be text. Bytes that are not valid UTF-8 are a
/// domain that cannot be right, rather than data that merely stopped.
#[test]
fn invalid_domain_bytes_are_reported() {
    let mut bytes = vec![3u8, 0xFF, 0xFE, 0];
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[0x99; SIGNATURE_LENGTH]);

    assert_refused(
        Owid::from_byte_array(&bytes),
        ParseStatus::InvalidDomainEncoding,
    );
}

/// The same statuses arrive through the standard conversions, so a caller
/// using `parse` or `try_into` is told as much as one calling the named
/// methods.
#[test]
fn standard_conversions_report_the_same_reasons() {
    let error = "not base 64!"
        .parse::<Owid>()
        .expect_err("should refuse the string");
    assert_eq!(error.status(), ParseStatus::InvalidBase64);

    let bytes: &[u8] = &[9, 9, 9];
    let error = Owid::try_from(bytes).expect_err("should refuse the bytes");
    assert_eq!(error.status(), ParseStatus::UnsupportedVersion);
}

/// A failure never carries any part of the input, so logging one cannot
/// log whatever an untrusted sender chose to put in it.
#[test]
fn a_failure_never_repeats_the_input() {
    let secret = "SECRETVALUE";
    let mut bytes = vec![3u8];
    bytes.extend_from_slice(secret.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(&99u32.to_le_bytes());
    bytes.extend_from_slice(&[0x99; SIGNATURE_LENGTH]);

    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    let message = error.to_string();
    assert!(
        !message.contains(secret),
        "the message repeated the input: {message}"
    );
    assert!(
        !message.chars().any(char::is_control),
        "the message should carry no control characters: {message:?}"
    );
}

/// A read cannot fetch a key or check a signature, whatever the bytes say.
///
/// The reading methods take bytes and nothing else, so there is no key, no
/// crypto instance and no network for them to reach, and a `ParseError` has
/// no status that could report a key or a transport failure even if there
/// were. This test names a domain that can never resolve, RFC 6761 reserving
/// `.invalid` for exactly that, and shows the answer is the structural one.
/// With the `fetch` feature enabled, a read that tried to reach the domain
/// would have to wait for that name to fail to resolve.
#[test]
fn a_failed_read_fetches_no_key() {
    let mut bytes = vec![3u8];
    bytes.extend_from_slice(b"creator.invalid");
    bytes.push(0);
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    // A declaration of a megabyte with nothing behind it.
    bytes.extend_from_slice(&(1024u32 * 1024).to_le_bytes());
    bytes.extend_from_slice(&[0x99; SIGNATURE_LENGTH]);

    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    assert_eq!(
        error.status(),
        ParseStatus::ByteCountMismatch,
        "the answer should be the structural one"
    );
}

/// An identifier whose envelope is well formed but whose signature does not
/// match reads successfully and then fails verification. Two questions, two
/// answers, and a read says nothing about the signature.
#[test]
fn a_valid_envelope_with_a_bad_signature_parses_then_fails_verification() {
    let crypto = Crypto::new();
    let creator = Creator::new(DOMAIN, crypto.clone()).expect("should create the creator");
    let signed = creator.create("Hello World").expect("should create");
    let mut bytes = signed.as_byte_array().expect("should serialize");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;

    let owid = Owid::from_byte_array(&bytes).expect("a bad signature should still parse");

    assert_eq!(
        owid.signature().len(),
        SIGNATURE_LENGTH,
        "the signature field is the right length, it just does not match"
    );
    assert!(
        !owid
            .verify_with_crypto(&crypto, &[])
            .expect("should run verification"),
        "verification should fail"
    );
    assert_eq!(
        owid.verify_status_with_crypto(&crypto, &[]),
        SignatureStatus::Invalid,
        "a signature that does not match is the one status meaning distrust"
    );
}

/// A key that cannot be read is never reported as a signature that does not
/// match. On 30 August 2026 the key end points served PEM a strict parser
/// rejects, and every verification against them failed while the keys and
/// the identifiers were both fine.
#[test]
fn a_key_that_cannot_be_read_is_not_an_invalid_signature() {
    let owid = creator().create("Hello World").expect("should create");

    for pem in ["", "not a PEM at all", "-----BEGIN PUBLIC KEY-----\nAAAA\n"] {
        assert_eq!(
            owid.verify_status_with_public_key(pem, &[]),
            SignatureStatus::InvalidKey,
            "a key that cannot be read should not read as a forgery"
        );
    }
}

/// A key that could not be obtained at all is not a signature that does not
/// match either. The request here fails in the transport before anything
/// leaves the machine, because the scheme is not one it can use, so the test
/// needs no network and no key end point.
#[cfg(feature = "fetch")]
#[test]
fn a_key_that_cannot_be_obtained_is_not_an_invalid_signature() {
    let owid = creator().create("Hello World").expect("should create");

    assert_eq!(
        owid.verify_status("no-such-scheme", &[]),
        SignatureStatus::KeyUnavailable,
        "a key that could not be fetched should not read as a forgery"
    );
}

/// Creating is the second of the two routes to an OWID, and it always
/// signs. There is no step at which a caller holds an unsigned one.
#[test]
fn creating_always_signs() {
    let crypto = Crypto::new();
    let creator = Creator::new(DOMAIN, crypto.clone()).expect("should create the creator");

    for owid in [
        creator.create("Hello World").expect("should create"),
        creator.create(b"bytes".to_vec()).expect("should create"),
        creator
            .create_with_others(b"bytes".to_vec(), &[])
            .expect("should create"),
    ] {
        assert_eq!(
            owid.signature().len(),
            SIGNATURE_LENGTH,
            "a created OWID always carries a signature"
        );
        assert_eq!(owid.domain(), DOMAIN, "the creator owns the domain");
        assert_eq!(
            owid.verify_status_with_crypto(&crypto, &[]),
            SignatureStatus::Valid,
            "a created OWID verifies with the key that made it"
        );
    }
}

/// Everything a library user could do before construction was closed they
/// can still do through the creator, including signing over other OWIDs as
/// a processor adding itself to a transaction.
#[test]
fn a_library_user_can_still_do_everything() {
    let root_crypto = Crypto::new();
    let root = Creator::new("root.com", root_crypto.clone())
        .expect("should create the root creator")
        .create("root")
        .expect("should create the root");

    let processor_crypto = Crypto::new();
    let processor = Creator::new("processor.com", processor_crypto.clone())
        .expect("should create the processor creator");
    let response = processor
        .create_with_others(b"response".to_vec(), &[&root])
        .expect("should create over the others");

    assert_eq!(
        response.verify_status_with_crypto(&processor_crypto, &[&root]),
        SignatureStatus::Valid,
        "should verify with the same others"
    );
    assert_eq!(
        response.verify_status_with_crypto(&processor_crypto, &[]),
        SignatureStatus::Invalid,
        "should fail without the others"
    );
    assert_eq!(
        root.verify_status_with_public_key(
            &root_crypto.public_key_pem().expect("should export"),
            &[]
        ),
        SignatureStatus::Valid,
        "the root should verify with its own public key"
    );
}

/// The bytes handed out are a read only view of what the OWID holds. A
/// caller can copy them, and the copy is theirs, but there is no way to
/// write through the view, which the `compile_fail` example on
/// `Owid::payload` proves.
#[test]
fn returned_bytes_are_a_view_of_the_owid() {
    let owid = creator().create("Hello World").expect("should create");

    let mut copy = owid.payload().to_vec();
    copy[0] ^= 0xFF;

    assert_ne!(
        copy.as_slice(),
        owid.payload(),
        "changing a copy should not change the OWID"
    );
    assert_eq!(
        owid.payload_as_string(),
        "Hello World",
        "the OWID should still carry what it was created with"
    );
}

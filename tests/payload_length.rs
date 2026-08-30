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

//! The payload length field of an OWID is whatever the sender declared, so
//! parsing must check it against the bytes present before sizing anything
//! by it. These tests prove that a declared length that does not leave
//! exactly the signature after the payload is refused, that refusing it
//! costs no allocation sized by the declared number, and that a correctly
//! sized envelope still parses. The 64 byte signature is the fixed tail
//! every valid OWID ends with. Mirrors PayloadLengthTests in owid-dotnet.
//! This crate only parses in memory buffers, so the non seekable stream
//! case in the .NET suite has no counterpart here.
//!
//! The domain field is the other part of an envelope whose length the
//! sender controls, because the parser finds its end by reading forward to
//! a null terminator, so the tests for the bound on that read live here as
//! well and share the counting allocator, which a test binary can only
//! register once. The same maximum binds what this crate writes, so the
//! tests that a longer domain is refused when a creator is built, and
//! again when an OWID carrying one is serialized, are here too. The unit
//! tests in `src/creator.rs` and `src/io.rs` check the same boundary
//! against the constant itself, which an integration test can not see.
//! The write bound is checked there as well, because an OWID carrying a
//! domain a creator would refuse can no longer be assembled from outside
//! the crate.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use owid::{Creator, Crypto, Error, Owid, ParseDetail, ParseStatus, Version, SIGNATURE_LENGTH};

thread_local! {
    /// Bytes requested from the allocator on this thread since the count
    /// was last reset.
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}

/// Counts the bytes each thread requests so a test can bound what a
/// refused parse costs. Every test runs on a separate thread, so a count
/// taken on one thread is not disturbed by the other tests in this file.
/// The count uses `try_with` so the allocator never panics if a thread is
/// allocating while its thread local storage is being torn down.
struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count(layout.size());
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count(new_size);
        System.realloc(ptr, layout, new_size)
    }
}

fn count(bytes: usize) {
    let _ = ALLOCATED.try_with(|a| a.set(a.get().wrapping_add(bytes)));
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

/// Runs the closure and returns its result with the bytes requested from
/// the allocator on this thread while it ran.
fn allocated_by<T>(run: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATED.with(|a| a.set(0));
    let result = run();
    (result, ALLOCATED.with(|a| a.get()))
}

const DOMAIN: &str = "51d.es";

/// A version 3 envelope, being the version byte, the domain with its
/// terminator, four minute bytes, the declared payload length, the payload
/// bytes given and the signature bytes given, so a test can make the
/// declared length and the bytes present disagree.
fn envelope(declared: u32, payload: &[u8], signature: &[u8]) -> Vec<u8> {
    envelope_with_domain(DOMAIN, declared, payload, signature)
}

/// The same envelope with the domain chosen by the caller, so a test can
/// make the domain longer than a domain name is allowed to be.
fn envelope_with_domain(domain: &str, declared: u32, payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut bytes = vec![Version::Version3.as_byte()];
    bytes.extend_from_slice(domain.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(&declared.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(signature);
    bytes
}

/// A domain of the length given, built from labels of the 63 characters
/// RFC 1035 section 2.3.4 allows, separated by dots, so the value is a
/// domain in shape as well as in length.
fn domain_of_length(length: usize) -> String {
    let mut value = String::new();
    while value.len() < length {
        if !value.is_empty() {
            value.push('.');
        }
        let label = (length - value.len()).min(63);
        for _ in 0..label {
            value.push('a');
        }
    }
    assert_eq!(value.len(), length, "should build the length asked for");
    value
}

fn payload() -> Vec<u8> {
    vec![0x5A; 37]
}

fn signature() -> Vec<u8> {
    vec![0x99; SIGNATURE_LENGTH]
}

/// The declared length matches the bytes present, the signature is the
/// last 64 bytes, and the envelope parses to the same payload. The parse
/// is measured as well, and must have requested at least the payload and
/// signature bytes it copied, which proves the allocation count sees what
/// the parser does and so the bound in the mismatched declaration test is
/// real.
#[test]
fn declared_length_matches_parses() {
    let payload = payload();
    let signature = signature();
    let bytes = envelope(payload.len() as u32, &payload, &signature);
    let (result, allocated) = allocated_by(|| Owid::from_byte_array(&bytes));
    let owid = result.expect("should parse");
    assert_eq!(owid.payload(), payload, "payload should round trip");
    assert_eq!(owid.signature(), signature, "signature should round trip");
    assert_eq!(owid.domain(), DOMAIN, "domain should round trip");
    assert!(
        allocated >= payload.len() + signature.len(),
        "a parse that copies {} bytes requested only {allocated}",
        payload.len() + signature.len()
    );
}

/// A payload that is materially larger than ordinary identifiers remains
/// valid when the declaration and bytes agree. This is a regression check
/// against introducing an implementation policy limit into format parsing.
#[test]
fn matching_one_mebibyte_payload_parses() {
    let payload = vec![0x5a; 1024 * 1024];
    let bytes = envelope(payload.len() as u32, &payload, &signature());

    let parsed = Owid::from_byte_array(&bytes).expect("matching payload should parse");

    assert_eq!(parsed.payload(), payload);
}

/// A round trip through the crate's own signing path still parses, so the
/// check agrees with what the crate itself produces.
#[test]
fn library_output_parses() {
    let creator = Creator::new(DOMAIN, Crypto::new()).expect("should create the creator");
    let original = creator
        .create_string("Hello World")
        .expect("should create the OWID");
    let bytes = original.as_byte_array().expect("should serialize");
    let parsed = Owid::from_byte_array(&bytes).expect("should parse the crate output");
    assert_eq!(
        parsed.payload(),
        original.payload(),
        "payload should round trip"
    );
    assert_eq!(
        parsed.signature(),
        original.signature(),
        "signature should round trip"
    );
    assert_eq!(
        parsed.domain(),
        original.domain(),
        "domain should round trip"
    );
}

/// One more or one fewer than the bytes present is refused, because either
/// leaves something other than exactly the signature at the end. The
/// failure names the declared count and the count present so the reader of
/// a log can see which one is wrong, and neither is any part of the input.
#[test]
fn declared_length_off_by_one_is_refused() {
    let payload = payload();
    let signature = signature();
    let present = payload.len() as i64;
    for declared in [payload.len() as u32 - 1, payload.len() as u32 + 1] {
        let bytes = envelope(declared, &payload, &signature);
        let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
        assert_eq!(
            error.status(),
            ParseStatus::ByteCountMismatch,
            "declared {declared} should be refused as a mismatch"
        );
        assert_eq!(
            error.detail(),
            ParseDetail::ByteCounts { declared, present },
            "the detail should name both counts"
        );
        let message = error.to_string();
        assert!(
            !message.chars().any(char::is_control),
            "message must not contain control characters: {message:?}"
        );
        assert_eq!(
            message,
            format!("ByteCountMismatch: declared '{declared}' with '{present}' present"),
            "message should name both counts"
        );
    }
}

/// A byte after the signature is refused, because the signature must be
/// the end of the envelope.
#[test]
fn trailing_byte_after_signature_is_refused() {
    let payload = payload();
    let mut bytes = envelope(payload.len() as u32, &payload, &signature());
    bytes.push(0);
    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    assert_eq!(
        error.status(),
        ParseStatus::ByteCountMismatch,
        "a trailing byte should be refused as a mismatch"
    );
}

/// A short signature is refused as a mismatch. The declared payload length
/// is right for the payload, but the bytes after it are fewer than a
/// signature, so the declaration cannot leave exactly the signature the
/// version requires. That is the finding whichever way the bytes fall
/// short, including when the buffer also stopped early.
#[test]
fn short_signature_is_refused() {
    let payload = payload();
    let bytes = envelope(
        payload.len() as u32,
        &payload,
        &[0x99; SIGNATURE_LENGTH - 1],
    );
    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    assert_eq!(
        error.status(),
        ParseStatus::ByteCountMismatch,
        "a short signature should be refused as a mismatch"
    );
    assert_eq!(
        error.detail(),
        ParseDetail::ByteCounts {
            declared: payload.len() as u32,
            present: payload.len() as i64 - 1
        },
        "the count present should be one short of the declaration"
    );
}

/// A buffer holding fewer bytes after the length field than a signature
/// needs gives a negative count present rather than one that has wrapped
/// round to something enormous, so it can never equal a declaration.
#[test]
fn fewer_bytes_than_a_signature_gives_a_negative_count() {
    let bytes = envelope(0, &[], &[0x99; 4]);
    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    assert_eq!(
        error.status(),
        ParseStatus::ByteCountMismatch,
        "a buffer with no room for a signature should be a mismatch"
    );
    assert_eq!(
        error.detail(),
        ParseDetail::ByteCounts {
            declared: 0,
            present: 4 - SIGNATURE_LENGTH as i64
        },
        "the count present should be negative"
    );
}

/// A large declaration whose payload bytes are absent is refused without
/// an allocation sized by the declared number. The envelope is a few dozen
/// bytes while declaring 64 MiB, then 2 GiB, then the most an unsigned 32
/// bit length can hold. The numeric values remain valid when the matching
/// payload is present, while each malformed refusal here requests under
/// 64 KiB from the allocator.
#[test]
fn mismatched_large_declaration_is_refused_without_allocating() {
    for declared in [64u32 * 1024 * 1024, 0x7FFF_FFFF, 0xFFFF_FFFF] {
        let bytes = envelope(declared, &[], &[]);
        let (result, allocated) = allocated_by(|| Owid::from_byte_array(&bytes));
        let error = result.expect_err("should refuse");
        assert_eq!(
            error.status(),
            ParseStatus::ByteCountMismatch,
            "declared {declared} should be refused as a mismatch"
        );
        assert!(
            matches!(
                error.detail(),
                ParseDetail::ByteCounts { declared: d, .. } if d == declared
            ),
            "the detail should name the declared count, got {:?}",
            error.detail()
        );
        assert!(
            allocated < 64 * 1024,
            "declared {declared} allocated {allocated} bytes"
        );
    }
}

/// An empty payload with a declared length of zero and a full signature
/// parses, so the check does not mistake a legitimate zero for a mismatch.
#[test]
fn empty_payload_parses() {
    let signature = signature();
    let bytes = envelope(0, &[], &signature);
    let owid = Owid::from_byte_array(&bytes).expect("should parse");
    assert!(owid.payload().is_empty(), "payload should be empty");
    assert_eq!(owid.signature(), signature, "signature should round trip");
}

/// A domain of exactly the maximum length parses and round trips. These
/// tests spell the number out rather than reading the constant in the
/// parser, which is private to the crate, so that a change to that
/// constant shows up here as a failure rather than quietly moving the
/// boundary the tests check. Where the number comes from is written
/// alongside the constant in `src/io.rs`.
#[test]
fn domain_of_maximum_length_parses() {
    let domain = domain_of_length(253);
    let payload = payload();
    let signature = signature();
    let bytes = envelope_with_domain(&domain, payload.len() as u32, &payload, &signature);
    let owid = Owid::from_byte_array(&bytes).expect("the longest valid domain should parse");
    assert_eq!(owid.domain(), domain, "domain should round trip");
    assert_eq!(owid.payload(), payload, "payload should round trip");
    assert_eq!(owid.signature(), signature, "signature should round trip");
}

/// One character more than the maximum is refused. The terminator sits at
/// the very next byte, so a read that went one character further would
/// accept this envelope, which is what makes the test prove where the read
/// stops.
#[test]
fn domain_over_maximum_is_refused() {
    let domain = domain_of_length(254);
    let payload = payload();
    let bytes = envelope_with_domain(&domain, payload.len() as u32, &payload, &signature());
    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    assert_eq!(
        error.status(),
        ParseStatus::InvalidDomainEncoding,
        "a domain one character over the maximum should be refused"
    );
    assert_eq!(
        error.to_string(),
        "InvalidDomainEncoding: longer than the '253' character maximum, or not terminated",
        "message should name the maximum"
    );
}

/// A buffer whose domain field has no terminator at all is refused, and
/// the refusal costs the same whatever the buffer is. The buffers here are
/// 1 MiB and 16 MiB of domain characters with no zero byte anywhere, and
/// each refusal requests under 64 KiB from the allocator, so nothing is
/// sized by the length of the input.
#[test]
fn unterminated_domain_is_refused_without_allocating() {
    for length in [1024 * 1024, 16 * 1024 * 1024] {
        let mut bytes = vec![Version::Version3.as_byte()];
        bytes.resize(length, b'a');
        let (result, allocated) = allocated_by(|| Owid::from_byte_array(&bytes));
        let error = result.expect_err("should refuse");
        assert_eq!(
            error.status(),
            ParseStatus::InvalidDomainEncoding,
            "an unterminated domain should be refused"
        );
        assert!(
            allocated < 64 * 1024,
            "a {length} byte buffer allocated {allocated} bytes"
        );
    }
}

/// A buffer whose only domain terminator sits 16 MiB in is refused, and
/// refusing it requests under 64 KiB from the allocator. This is the case
/// that puts a number on the bound. A read that walked to the terminator
/// would find one, and would then copy every byte up to it into the domain
/// string, so the allocator would see the whole 16 MiB. Seeing well under
/// 64 KiB instead says the read stopped at the maximum length a domain
/// name may be, and that the terminator further on was never reached.
#[test]
fn far_terminator_domain_is_refused_without_copying_the_buffer() {
    let length = 16 * 1024 * 1024;
    let mut bytes = vec![Version::Version3.as_byte()];
    bytes.resize(length, b'a');
    bytes.push(0);
    let (result, allocated) = allocated_by(|| Owid::from_byte_array(&bytes));
    let error = result.expect_err("should refuse");
    assert_eq!(
        error.status(),
        ParseStatus::InvalidDomainEncoding,
        "a terminator beyond the maximum should be refused"
    );
    assert!(
        allocated < 64 * 1024,
        "a terminator {length} bytes in allocated {allocated} bytes"
    );
}

/// A buffer that runs out before the domain terminator, and is shorter
/// than a domain may be, is still the end of buffer error it was before
/// the bound was added, so the bound has not taken over an unrelated case.
#[test]
fn short_unterminated_domain_is_end_of_buffer() {
    let bytes = vec![Version::Version3.as_byte(), b'a', b'b', b'c'];
    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    assert_eq!(
        error.status(),
        ParseStatus::UnexpectedEnd,
        "a short unterminated domain should be an unexpected end"
    );
}

/// A creator can not be built for a domain one character over the
/// maximum, so the crate can not sign an OWID whose domain it would then
/// refuse to read. The bound is applied where the caller supplies the
/// domain, so the refusal arrives before any signing or serializing.
#[test]
fn creator_over_maximum_domain_is_refused() {
    let domain = domain_of_length(254);
    let error = Creator::new(&domain, Crypto::new()).expect_err("should refuse");
    assert!(
        matches!(error, Error::DomainTooLong),
        "a creator domain over the maximum should be refused, got {error:?}"
    );
    assert_eq!(
        error.to_string(),
        "domain field exceeds the '253' character maximum",
        "message should name the maximum"
    );
}

/// The crate signs and parses back an OWID whose domain is the maximum
/// length, so the bound agrees with what the crate itself writes at the
/// boundary and not only with hand built buffers.
#[test]
fn library_output_with_maximum_domain_parses() {
    let domain = domain_of_length(253);
    let creator = Creator::new(&domain, Crypto::new()).expect("should create the creator");
    let original = creator
        .create_string("Hello World")
        .expect("should create the OWID");
    let bytes = original.as_byte_array().expect("should serialize");
    let parsed = Owid::from_byte_array(&bytes).expect("should parse the crate output");
    assert_eq!(parsed.domain(), domain, "domain should round trip");
    assert_eq!(
        parsed.payload(),
        original.payload(),
        "payload should round trip"
    );
    assert_eq!(
        parsed.signature(),
        original.signature(),
        "signature should round trip"
    );
}

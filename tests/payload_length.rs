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

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use owid::{Creator, Crypto, Error, Owid, Version, SIGNATURE_LENGTH};

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
    let mut bytes = vec![Version::Version3.as_byte()];
    bytes.extend_from_slice(DOMAIN.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1000u32.to_le_bytes());
    bytes.extend_from_slice(&declared.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(signature);
    bytes
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
    assert_eq!(owid.payload, payload, "payload should round trip");
    assert_eq!(owid.signature, signature, "signature should round trip");
    assert_eq!(owid.domain, DOMAIN, "domain should round trip");
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

    assert_eq!(parsed.payload, payload);
}

/// A round trip through the crate's own signing path still parses, so the
/// check agrees with what the crate itself produces.
#[test]
fn library_output_parses() {
    let creator = Creator::new(DOMAIN, Crypto::new()).expect("should create the creator");
    let original = creator
        .sign_string("Hello World")
        .expect("should sign the OWID");
    let bytes = original.as_byte_array().expect("should serialize");
    let parsed = Owid::from_byte_array(&bytes).expect("should parse the crate output");
    assert_eq!(
        parsed.payload, original.payload,
        "payload should round trip"
    );
    assert_eq!(
        parsed.signature, original.signature,
        "signature should round trip"
    );
    assert_eq!(parsed.domain, original.domain, "domain should round trip");
}

/// One more or one fewer than the bytes present is refused, because either
/// leaves something other than exactly the signature at the end. The error
/// names the declared length and the bytes present so the reader of a log
/// can see which one is wrong.
#[test]
fn declared_length_off_by_one_is_refused() {
    let payload = payload();
    let signature = signature();
    let present = payload.len() + signature.len();
    for declared in [payload.len() as u32 - 1, payload.len() as u32 + 1] {
        let bytes = envelope(declared, &payload, &signature);
        let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
        assert!(
            matches!(
                error,
                Error::PayloadLengthMismatch {
                    declared: d,
                    present: p
                } if d == declared && p == present
            ),
            "declared {declared} should be refused as a mismatch, got {error:?}"
        );
        let message = error.to_string();
        assert!(
            !message.chars().any(char::is_control),
            "message must not contain control characters: {message:?}"
        );
        assert_eq!(
            message,
            format!(
                "OWID payload length '{declared}' does not match the \
                 '{present}' bytes present, of which the final '64' must \
                 be the signature"
            ),
            "message should name both lengths"
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
    assert!(
        matches!(error, Error::PayloadLengthMismatch { .. }),
        "trailing byte should be refused as a mismatch, got {error:?}"
    );
}

/// A short signature is refused. The declared payload length is right for
/// the payload, but the bytes after it are fewer than a signature.
#[test]
fn short_signature_is_refused() {
    let payload = payload();
    let bytes = envelope(
        payload.len() as u32,
        &payload,
        &[0x99; SIGNATURE_LENGTH - 1],
    );
    let error = Owid::from_byte_array(&bytes).expect_err("should refuse");
    assert!(
        matches!(error, Error::PayloadLengthMismatch { .. }),
        "short signature should be refused as a mismatch, got {error:?}"
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
        assert!(
            matches!(error, Error::PayloadLengthMismatch { declared: d, .. } if d == declared),
            "declared {declared} should be refused as a mismatch, got {error:?}"
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
    assert!(owid.payload.is_empty(), "payload should be empty");
    assert_eq!(owid.signature, signature, "signature should round trip");
}

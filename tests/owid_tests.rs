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

//! Tests for [`Owid`] and [`Creator`]. Ports of the test suites in the .NET
//! and Go implementations so that the behavior matches across languages.

use owid::{Creator, Crypto, Error, Owid, ParseStatus, SignatureStatus, SIGNATURE_LENGTH};

const TEST_TEXT: &str = "Hello World";
const TEST_DOMAIN: &str = "test.com";

/// Mirrors the .NET TestInitialize. Generates a key pair and returns the
/// PEM forms so that tests exercise the import paths.
struct Fixture {
    public_pem: String,
    private_pem: String,
}

impl Fixture {
    fn new() -> Self {
        let crypto = Crypto::new();
        let fixture = Fixture {
            public_pem: crypto
                .public_key_pem()
                .expect("should export the public key"),
            private_pem: crypto
                .private_key_pem()
                .expect("should export the private key"),
        };
        Crypto::new_verify_only(&fixture.public_pem).expect("should import the public key");
        Crypto::new_sign_only(&fixture.private_pem).expect("should import the private key");
        fixture
    }

    fn creator(&self) -> Creator {
        let crypto =
            Crypto::new_sign_only(&self.private_pem).expect("should import the private key");
        Creator::new(TEST_DOMAIN, crypto).expect("should create the creator")
    }

    fn verifier(&self) -> Crypto {
        Crypto::new_verify_only(&self.public_pem).expect("should import the public key")
    }

    fn create_owid(&self) -> Owid {
        self.creator()
            .create(TEST_TEXT)
            .expect("should create the OWID")
    }
}

/// Tampering reaches a verifier as bytes, so a test that wants a changed
/// OWID changes the serialized form and reads it back. The fields of an
/// OWID cannot be changed in memory, which is the point of them being read
/// only, so this is the only way to hold one whose signature no longer
/// describes it.
fn tampered(owid: &Owid, index: usize) -> Owid {
    let mut bytes = owid.as_byte_array().expect("should serialize");
    // The low bit only, so a letter in the domain stays a letter and the
    // envelope still parses. What is being tested is that a changed field
    // fails verification, not that a broken envelope fails to parse.
    bytes[index] ^= 0x01;
    Owid::from_byte_array(&bytes).expect("should still parse")
}

/// Port of the .NET TestCreate test. Creation, verification, and base 64
/// round trip.
#[test]
fn create() {
    let fixture = Fixture::new();
    let original = fixture.create_owid();

    let valid = original
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should verify the original");
    assert!(valid, "original should verify");

    let encoded = original.as_base64().expect("should encode to base 64");
    let copy = Owid::from_base64(&encoded).expect("should decode from base 64");
    let valid = copy
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should verify the copy");
    assert!(valid, "copy should verify");
}

/// Port of the .NET TestVerificationFailsWithInvalidSignature test.
#[test]
fn verification_fails_with_invalid_signature() {
    let fixture = Fixture::new();
    let signed = fixture.create_owid();
    let length = signed.as_byte_array().expect("should serialize").len();
    // The signature is the last SIGNATURE_LENGTH bytes of the envelope.
    let owid = tampered(&signed, length - SIGNATURE_LENGTH);

    let valid = owid
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should run verification");
    assert!(!valid, "verification should fail with corrupted signature");
}

/// Port of the .NET TestVerificationFailsWithWrongPublicKey test.
#[test]
fn verification_fails_with_wrong_public_key() {
    let fixture = Fixture::new();
    let owid = fixture.create_owid();

    let wrong_key = Crypto::new();
    let valid = owid
        .verify_with_crypto(&wrong_key, &[])
        .expect("should run verification");
    assert!(!valid, "verification should fail with the wrong public key");
}

/// Port of the .NET TestCreateWithEmptyPayload test.
#[test]
fn create_with_empty_payload() {
    let fixture = Fixture::new();
    let owid = fixture
        .creator()
        .create(Vec::new())
        .expect("should create the OWID");

    let valid = owid
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should verify");
    assert!(valid, "OWID with empty payload should verify");
}

/// Port of the .NET TestCreateWithLargePayload test. Uses ten thousand
/// bytes of varied data.
#[test]
fn create_with_large_payload() {
    let fixture = Fixture::new();
    let large_payload: Vec<u8> = (0..10_000u32)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7) % 256) as u8)
        .collect();
    let owid = fixture
        .creator()
        .create(large_payload.clone())
        .expect("should create the OWID");

    let valid = owid
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should verify");
    assert!(valid, "OWID with large payload should verify");

    let copy = Owid::from_base64(&owid.as_base64().expect("should encode")).expect("should decode");
    assert_eq!(copy.payload(), large_payload, "payload should round trip");
}

/// Port of the .NET TestCreatorSignWithStringPayload test.
#[test]
fn creator_create_with_string_payload() {
    let fixture = Fixture::new();
    let owid = fixture
        .creator()
        .create(TEST_TEXT)
        .expect("should create from the string");

    assert_eq!(
        owid.payload_as_string(),
        TEST_TEXT,
        "payload as string should match"
    );

    let valid = owid
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should verify");
    assert!(valid, "OWID should verify");
}

/// Port of the .NET TestCreatorSignWithBytePayload test.
#[test]
fn creator_create_with_byte_payload() {
    let fixture = Fixture::new();
    let payload = TEST_TEXT.as_bytes().to_vec();
    let owid = fixture
        .creator()
        .create(payload.clone())
        .expect("should create from the bytes");

    assert_eq!(owid.payload(), payload, "payload bytes should match");

    let valid = owid
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should verify");
    assert!(valid, "OWID should verify");
}

/// Port of the .NET TestCreatorSetsDomain test. The creator owns the
/// domain, so a caller has no way to ask for a different one.
#[test]
fn creator_sets_domain() {
    let fixture = Fixture::new();
    let owid = fixture
        .creator()
        .create(TEST_TEXT)
        .expect("should create the OWID");

    assert_eq!(owid.domain(), TEST_DOMAIN, "creator should set the domain");
}

/// Port of the .NET TestSerializationRoundtrip test. Multiple encode and
/// decode cycles maintain integrity.
#[test]
fn serialization_roundtrip() {
    let fixture = Fixture::new();
    let original = fixture.create_owid();

    let encoded1 = original.as_base64().expect("should encode");
    let decoded1 = Owid::from_base64(&encoded1).expect("should decode");
    let encoded2 = decoded1.as_base64().expect("should encode again");
    let decoded2 = Owid::from_base64(&encoded2).expect("should decode again");

    assert_eq!(encoded1, encoded2, "encodings should be identical");
    for owid in [&original, &decoded1, &decoded2] {
        let valid = owid
            .verify_with_crypto(&fixture.verifier(), &[])
            .expect("should verify");
        assert!(valid, "every round trip should verify");
    }
}

/// Port of the .NET TestInvalidBase64Throws test.
#[test]
fn invalid_base64_errors() {
    let result = Owid::from_base64("This is not valid Base64!@#$");
    assert_eq!(
        ParseStatus::of(&result),
        ParseStatus::InvalidBase64,
        "invalid base 64 should report the reason"
    );
}

/// Port of the .NET TestBatchSigningAndVerification test.
#[test]
fn batch_signing_and_verification() {
    const BATCH_SIZE: usize = 10;
    let fixture = Fixture::new();
    let creator = fixture.creator();

    let owids: Vec<Owid> = (0..BATCH_SIZE)
        .map(|i| {
            creator
                .create(format!("Payload {i}").into_bytes())
                .expect("should create from the payload")
        })
        .collect();

    let verifier = fixture.verifier();
    for owid in &owids {
        let valid = owid
            .verify_with_crypto(&verifier, &[])
            .expect("should verify");
        assert!(valid, "every OWID in the batch should verify");
    }
}

/// Port of the .NET TestModifiedDomainFailsVerification test.
#[test]
fn modified_domain_fails_verification() {
    let fixture = Fixture::new();
    // Byte 1 is the first character of the domain, which follows the
    // version byte.
    let owid = tampered(&fixture.create_owid(), 1);
    assert_ne!(
        owid.domain(),
        TEST_DOMAIN,
        "the tampered copy should carry a different domain"
    );

    let valid = owid
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should run verification");
    assert!(!valid, "modified domain should fail verification");
}

/// Port of the Go TestOWIDVerify test using the public key PEM directly.
#[test]
fn verify_with_public_key_pem() {
    let fixture = Fixture::new();
    let owid = fixture.create_owid();

    let valid = owid
        .verify_with_public_key(&fixture.public_pem, &[])
        .expect("should verify with the PEM");
    assert!(valid, "OWID should verify with the public key PEM");
}

/// Port of the Go TestOWIDBase64 and TestOWIDString tests. The decoded copy
/// must compare equal on every field at the granularity stored.
#[test]
fn base64_roundtrip_compare() {
    let fixture = Fixture::new();
    let original = fixture.create_owid();

    let copy =
        Owid::from_base64(&original.as_base64().expect("should encode")).expect("should decode");

    assert_eq!(copy.version(), original.version(), "version should match");
    assert_eq!(copy.domain(), original.domain(), "domain should match");
    assert_eq!(copy.payload(), original.payload(), "payload should match");
    assert_eq!(
        copy.signature(),
        original.signature(),
        "signature should match"
    );
    assert_eq!(
        copy.date().timestamp() / 60,
        original.date().timestamp() / 60,
        "date should match to the minute"
    );
}

/// Port of the Go TestOWIDBase64CorruptShort test. Truncated base 64 must
/// error.
#[test]
fn base64_corrupt_short() {
    let fixture = Fixture::new();
    let encoded = fixture.create_owid().as_base64().expect("should encode");
    let result = Owid::from_base64(&encoded[..encoded.len() - 4]);
    assert!(result.is_err(), "truncated base 64 should error");
}

/// Port of the Go TestOWIDBase64CorruptMiss test. Base 64 missing the start
/// must error.
#[test]
fn base64_corrupt_missing_start() {
    let fixture = Fixture::new();
    let encoded = fixture.create_owid().as_base64().expect("should encode");
    let result = Owid::from_base64(&encoded[4..]);
    assert!(
        result.is_err() || {
            let owid = result.expect("checked above");
            !owid
                .verify_with_crypto(&fixture.verifier(), &[])
                .unwrap_or(false)
        },
        "base 64 missing the start should error or fail verification"
    );
}

/// Port of the Go TestOWIDByteArrayCorruptReplace test. Every single byte
/// corruption must either fail to parse or fail verification.
#[test]
fn byte_array_corrupt_every_byte() {
    let fixture = Fixture::new();
    let owid = fixture.create_owid();
    let bytes = owid.as_byte_array().expect("should encode");
    let verifier = fixture.verifier();

    for i in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[i] = corrupted[i].wrapping_add(1);
        let still_valid = match Owid::from_byte_array(&corrupted) {
            // A parse failure is an acceptable detection of the corruption.
            Err(_) => false,
            Ok(parsed) => parsed.verify_with_crypto(&verifier, &[]).unwrap_or(false),
        };
        assert!(
            !still_valid,
            "corruption of byte {i} should fail parsing or verification"
        );
    }
}

/// Signing an OWID together with others, as a processor does when adding
/// itself to a transaction, must verify with the same others and fail with
/// different others. Mirrors the sign and verify with others methods in the
/// .NET and Go implementations.
#[test]
fn sign_and_verify_with_others() {
    let root_fixture = Fixture::new();
    let root = root_fixture.create_owid();

    let processor_crypto = Crypto::new();
    let processor = Creator::new("processor.com", processor_crypto.clone())
        .expect("should create the processor creator");
    let response = processor
        .create_with_others(b"response".to_vec(), &[&root])
        .expect("should create with others");

    let valid = response
        .verify_with_crypto(&processor_crypto, &[&root])
        .expect("should verify with the same others");
    assert!(valid, "should verify with the same others");

    let valid = response
        .verify_with_crypto(&processor_crypto, &[])
        .expect("should run verification without the others");
    assert!(!valid, "should fail verification without the others");

    // A different payload guarantees different bytes. Signing is
    // deterministic, so an identical domain, date, and payload would
    // produce an identical OWID.
    let other_root = root_fixture
        .creator()
        .create(b"different root".to_vec())
        .expect("should create the other root");
    let valid = response
        .verify_with_crypto(&processor_crypto, &[&other_root])
        .expect("should run verification with different others");
    assert!(!valid, "should fail verification with different others");
}

/// An empty creator domain is rejected, mirroring the .NET configuration
/// validation.
#[test]
fn empty_domain_rejected() {
    let result = Creator::new("  ", Crypto::new());
    assert!(
        matches!(result, Err(Error::InvalidDomain(_))),
        "empty domain should be rejected"
    );
}

/// The empty marker is a single zero byte saying that an optional OWID is
/// not present, mirroring the EmptyToBuffer functions in the .NET and Go
/// implementations. A marker is not an OWID, so reading one as a complete
/// envelope is refused rather than handing back an OWID with nothing in it.
#[test]
fn empty_marker_is_not_an_owid() {
    let mut buffer = Vec::new();
    Owid::empty_to_buffer(&mut buffer);
    assert_eq!(buffer, vec![0], "empty marker should be a single zero byte");
    let result = Owid::from_byte_array(&buffer);
    assert_eq!(
        ParseStatus::of(&result),
        ParseStatus::UnsupportedVersion,
        "a marker should not read as an OWID"
    );
}

/// Unknown version bytes are rejected.
#[test]
fn unknown_version_rejected() {
    let result = Owid::from_byte_array(&[9]);
    assert_eq!(
        ParseStatus::of(&result),
        ParseStatus::UnsupportedVersion,
        "unknown version should be rejected"
    );
}

/// The signature constant matches the specification.
#[test]
fn signature_length_constant() {
    assert_eq!(SIGNATURE_LENGTH, 64, "signature length should be 64 bytes");
}

/// Port of the .NET TestModifiedPayloadFailsVerification test.
#[test]
fn modified_payload_fails_verification() {
    let fixture = Fixture::new();
    let signed = fixture.create_owid();
    // The payload follows the version byte, the domain and its terminator,
    // the four date bytes and the four length bytes.
    let index = 1 + TEST_DOMAIN.len() + 1 + 4 + 4;
    let owid = tampered(&signed, index);
    assert_ne!(
        owid.payload(),
        signed.payload(),
        "the tampered copy should carry a different payload"
    );

    let valid = owid
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should run verification");
    assert!(!valid, "modified payload should fail verification");
    assert_eq!(
        owid.verify_status_with_crypto(&fixture.verifier(), &[]),
        SignatureStatus::Invalid,
        "a signature that does not match is the one status meaning the \
         identifier should be distrusted"
    );
}

/// Non ASCII payloads survive the string APIs because Rust uses UTF-8, the
/// same as the Go and JavaScript implementations. The .NET implementation
/// is ASCII only, which is documented there as a divergence.
#[test]
fn non_ascii_payload_roundtrip() {
    let fixture = Fixture::new();
    let text = "h\u{e9}llo w\u{f6}rld \u{20ac}100";
    let owid = fixture
        .creator()
        .create(text)
        .expect("should create from the string");

    let copy = Owid::from_base64(&owid.as_base64().expect("should encode")).expect("should decode");
    assert_eq!(
        copy.payload_as_string(),
        text,
        "non ASCII payload should survive the round trip"
    );

    let valid = copy
        .verify_with_crypto(&fixture.verifier(), &[])
        .expect("should verify");
    assert!(valid, "OWID should verify");
}

/// Port of the .NET TestCreatorWithCorruptPrivateKeyThrows test. A PEM with
/// a valid header but corrupt content is rejected.
#[test]
fn corrupt_private_key_pem_rejected() {
    let corrupt = "-----BEGIN PRIVATE KEY-----\n\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\
        -----END PRIVATE KEY-----\n";
    let result = Crypto::new_sign_only(corrupt);
    assert!(result.is_err(), "corrupt private key PEM should error");
}

/// Port of the .NET date precision tests. Dates round trip floored to the
/// minute for versions 2 and 3 with no seconds component.
#[test]
fn date_precision_to_the_minute() {
    let fixture = Fixture::new();
    let owid = fixture.create_owid();

    let copy = Owid::from_base64(&owid.as_base64().expect("should encode")).expect("should decode");
    assert_eq!(
        copy.date().timestamp() % 60,
        0,
        "decoded date should have no seconds component"
    );
    assert_eq!(
        copy.date().timestamp() / 60,
        owid.date().timestamp() / 60,
        "decoded date should be the original floored to the minute"
    );
}

/// Port of the Go TestCreatorBatch uniqueness assertion. Different payloads
/// produce different OWIDs.
#[test]
fn batch_owids_unique() {
    let fixture = Fixture::new();
    let creator = fixture.creator();
    let mut encoded: Vec<String> = (0..10)
        .map(|i| {
            creator
                .create(format!("payload {i}").into_bytes())
                .expect("should create from the payload")
                .as_base64()
                .expect("should encode")
        })
        .collect();
    encoded.sort();
    encoded.dedup();
    assert_eq!(encoded.len(), 10, "all OWIDs in the batch should be unique");
}

/// Port of the Go TestCryptoSignatureAlignment test. Every signature is
/// exactly 64 bytes and verifies, covering r and s values that encode to
/// fewer than 32 bytes.
#[test]
fn signature_alignment() {
    let crypto = Crypto::new();
    for i in 0..100u32 {
        let data = format!("alignment test {i}");
        let signature = crypto
            .sign_byte_array(data.as_bytes())
            .expect("should sign the data");
        assert_eq!(
            signature.len(),
            SIGNATURE_LENGTH,
            "signature {i} should be 64 bytes"
        );
        let valid = crypto
            .verify_byte_array(data.as_bytes(), &signature)
            .expect("should verify the data");
        assert!(valid, "signature {i} should verify");
    }
}

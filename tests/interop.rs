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

//! Cross language interop tests. The fixtures were signed by the Go and .NET
//! implementations using throwaway P-256 key pairs whose public halves are
//! embedded below, so these tests prove that this implementation verifies
//! real signatures produced by the sibling libraries, not just its own.
//!
//! The fixtures were generated on 2026-06-12 by small harnesses built
//! against owid-go (with the signature alignment fix that right aligns the
//! r and s halves) and owid-dotnet. At generation time the full matrix was
//! checked, each of the Go, .NET, JavaScript, and Rust implementations
//! verified all of these fixtures and rejected tampered copies.
//!
//! Two cases per language. "simple" is an ASCII payload and "utf8" is a non
//! ASCII payload (the payloads were passed to .NET as UTF-8 bytes rather
//! than through its ASCII string overload).

use owid::Owid;

/// The non ASCII payload shared by the "utf8" fixtures.
const UTF8_PAYLOAD: &str = "Z\u{00fc}rich \u{2764} OWID \u{00a3}\u{20ac}";

/// Fixtures produced by one of the other language implementations.
struct LanguageFixtures {
    language: &'static str,
    domain: &'static str,
    public_key_spki: &'static str,
    simple: &'static str,
    utf8: &'static str,
}

const GO: LanguageFixtures = LanguageFixtures {
    language: "go",
    domain: "go.swan-demo.uk",
    public_key_spki: concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeO51FrQ8AmCFjLnePUH1qQ4GWGxj\n",
        "1aL5ux6vNJFSRnGTVc5YC8kEwqfOaMEjVWqt4Gbq4+lEnIAgTl76YAGpcA==\n",
        "-----END PUBLIC KEY-----\n"
    ),
    simple: concat!(
        "A2dvLnN3YW4tZGVtby51awA/vTMABwAAAGV4YW1wbGVPIQZ/uhIjVxrROjMDfcAkRk8U",
        "4fYacm0Ck4aOxoRDJPK/QrKavqZqCf7cCKbNuJ0aA7GhVeuy4ojeSzNX56Qn"
    ),
    utf8: concat!(
        "A2dvLnN3YW4tZGVtby51awA/vTMAFgAAAFrDvHJpY2gg4p2kIE9XSUQgwqPigqzxY+4Q",
        "gUGt84xC9HxHmHXDt+wcB0Y9a6E+Txm2F147Qacbp0CtrF8x7QCWZfkcKCKNGSM8hYZE",
        "fYjJtViG+tA+"
    ),
};

const DOTNET: LanguageFixtures = LanguageFixtures {
    language: "dotnet",
    domain: "dotnet.swan-demo.uk",
    public_key_spki: concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEec6dTi0JOYGP78lw7/zAjp3r73fZ\n",
        "A7zSi4Ov90sVxgmqZ4cI1sbj7AbsnBhqJDe5Hu14gDBjZWErL7KpkjEl0A==\n",
        "-----END PUBLIC KEY-----"
    ),
    simple: concat!(
        "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zAAcAAABleGFtcGxlVegwXS00P/DU2FJbLjof",
        "8qc/BwrffhbKJkV42pqFd7nUD+KR/DxxRSfLlm77/kAyR/dLOcwEetjN1z9UWzyh0w=="
    ),
    utf8: concat!(
        "A2RvdG5ldC5zd2FuLWRlbW8udWsAPb0zABYAAABaw7xyaWNoIOKdpCBPV0lEIMKj4oKs",
        "VuaeaDUej0sF+cHfYj/icDBmlBLOviC6ZE28am8EtY+IGuesFcg2rKMybcsAxMmnrDtF",
        "2xsk1cJvHgoIYpSJJQ=="
    ),
};

const LANGUAGES: [&LanguageFixtures; 2] = [&GO, &DOTNET];

/// Returns the fixture with the final byte of its serialized form, always
/// a signature byte, inverted.
///
/// The change is made to the bytes and read back, which is how tampering
/// actually reaches a verifier. An OWID cannot be changed in memory,
/// because its signature covers the fields as they arrived.
fn tamper(fixture: &str) -> Owid {
    let owid = Owid::from_base64(fixture).expect("should parse the fixture");
    let mut bytes = owid.as_byte_array().expect("should serialize");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    Owid::from_byte_array(&bytes).expect("a tampered signature should still parse")
}

/// Every fixture verifies with the public key of the language that signed
/// it.
#[test]
fn fixtures_verify() {
    for language in LANGUAGES {
        for fixture in [language.simple, language.utf8] {
            let owid = Owid::from_base64(fixture).expect("should parse the fixture");
            assert!(
                owid.verify_with_public_key(language.public_key_spki)
                    .expect("should verify"),
                "{} fixture should verify",
                language.language
            );
        }
    }
}

/// A corrupted signature byte fails verification for every fixture.
#[test]
fn tampered_fixtures_rejected() {
    for language in LANGUAGES {
        for fixture in [language.simple, language.utf8] {
            assert!(
                !tamper(fixture)
                    .verify_with_public_key(language.public_key_spki)
                    .expect("should verify"),
                "tampered {} fixture should not verify",
                language.language
            );
        }
    }
}

/// The non ASCII payload survives the trip through both languages, proving
/// the UTF-8 payload convention is shared.
#[test]
fn utf8_payloads_preserved() {
    for language in LANGUAGES {
        let owid = Owid::from_base64(language.utf8).expect("should parse the fixture");
        assert_eq!(
            owid.payload_as_string(),
            UTF8_PAYLOAD,
            "{} payload should decode as the UTF-8 text",
            language.language
        );
    }
}

/// The fixture fields decode to the values the generating harnesses used.
#[test]
fn fixture_fields_match() {
    for language in LANGUAGES {
        let owid = Owid::from_base64(language.simple).expect("should parse the fixture");
        assert_eq!(owid.domain(), language.domain, "domain should match");
        assert_eq!(owid.payload_as_string(), "example", "payload should match");
        assert_eq!(owid.signature().len(), 64, "signature should be 64 bytes");
    }
}

/// Parsing a fixture and serializing it again produces the identical base 64
/// string, proving the writer matches the bytes Go and .NET produced.
#[test]
fn fixtures_roundtrip_byte_exact() {
    for language in LANGUAGES {
        for fixture in [language.simple, language.utf8] {
            let owid = Owid::from_base64(fixture).expect("should parse the fixture");
            assert_eq!(
                owid.as_base64().expect("should serialize"),
                fixture,
                "{} fixture should round trip exactly",
                language.language
            );
        }
    }
}

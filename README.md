![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) Rust

## Overview

Open Web Id (OWID) is an open source cryptographically secure shared web
identifier schema. This repository implements OWID in Rust.

Read the [OWID](https://github.com/SWAN-community/owid) project to learn more
about the concepts before looking into this implementation.

## Scope of this implementation

This library creates, signs, serializes, and verifies OWIDs. It covers the
full library contract of the OWID specification, including reading the
deprecated earlier versions of the data structure.

The core crate performs no network access and compiles for WebAssembly
targets such as `wasm32-wasip1`, which makes it suitable for edge computing
environments. Two optional features extend it.

* `fetch` adds domain based verification that retrieves the creator public
  key over HTTP from the well known end point and caches it.
* `endpoints` adds framework agnostic helpers for hosting the well known end
  points that an OWID creator must serve.

## How an OWID comes into being

An OWID is only worth anything because it is signed, so this crate does not
let one exist in an unsigned state. There are exactly two ways an instance
reaches calling code.

1. `Owid::from_base64` or `Owid::from_byte_array` reads a complete
   serialized OWID. Data arriving from outside that is not an OWID is an
   ordinary outcome, so the answer is a `ParseError` naming the reason with
   a `ParseStatus`, and never anything raised.
2. `Creator::create_string` or `Creator::create_bytes` builds and signs one
   in a single step, owning the version, the domain, the date and the
   signature, while the caller supplies the payload.

There is no public constructor, the fields are private and read only, and
there is no public way to sign an OWID, because with no way to hold an
unsigned one there is nothing outside to sign and re-signing one would
replace a signature its fields were read with.

Whether bytes are an OWID and whether the signature on it is genuine are two
questions with two answers. A successful read says nothing about the
signature. `verify_status_with_public_key` answers the second question with
a `SignatureStatus` that keeps a signature that does not match apart from a
check that could not be made at all, so a key that cannot be fetched or
decoded never reads as a forgery.

## Payload size and application limits

The OWID wire format stores the payload length as an unsigned 32 bit value,
so a payload from zero through 4,294,967,295 bytes is structurally valid. The
format defines no smaller payload limit. The null terminated domain is capped
at 253 characters, so that field is at most 254 bytes with its terminator,
which leaves the payload as the only part of the envelope the protocol leaves
open ended, so the protocol alone is not an application input limit for the
complete envelope.

This crate validates that the declared payload length agrees with the bytes
present before it sizes or copies the payload. A large declaration without
the corresponding bytes is malformed and is rejected without allocating the
declared size. A matching large payload is not malformed merely because it is
large, and parsing work and memory use scale with the bytes actually present.

The 253 character domain maximum binds this crate on both sides. A buffer
whose domain field runs past it is refused when it is read, and a domain
longer than it is refused when a `Creator` is built and again when an OWID
carrying it is serialized, so the crate will not emit an OWID that it would
then refuse to read.

The owned APIs remain subject to the target's `usize`, address-space and
available-memory limits. Applications accepting untrusted OWIDs must choose
limits suitable for their use case and enforce them before buffering the
binary form or decoding Base64. An implementation capacity failure or an
application policy rejection is distinct from an invalid OWID.

For transport input, limit the complete HTTP body or encoded envelope,
allowing for the domain and the other OWID fields as well as the payload.
After parsing, `owid.payload().len()` reports the actual payload size
without another copy and can be used for downstream policy. The parser
cannot choose either limit on behalf of the application.

## Installation

Add the crate to `Cargo.toml`.

```toml
[dependencies]
owid = "2"
```

Enable the optional features as needed.

```toml
[dependencies]
owid = { version = "2", features = ["fetch", "endpoints"] }
```

## Usage

Create and sign an OWID, then verify it with the public key.

```rust
use owid::{Creator, Crypto, Owid};

// The creator operates a domain and holds the signing keys. Crypto::new
// generates a new ECDSA P-256 key pair. Keys can also be imported from PEM
// with Crypto::new_sign_only and Crypto::new_verify_only.
let crypto = Crypto::new();
let creator = Creator::new("example.com", crypto.clone()).unwrap();

// Creating and signing are one step, so an OWID never exists unsigned.
let owid = creator.create_string("Hello World").unwrap();

// Serialize to base 64 for storage or transmission.
let encoded = owid.as_base64().unwrap();

// Later, or elsewhere, read it back and verify with the creator public key.
let copy = Owid::from_base64(&encoded).unwrap();
let public_pem = crypto.public_key_pem().unwrap();
assert!(copy.verify_with_public_key(&public_pem, &[]).unwrap());
```

Read an OWID that came from outside, where data that is not an OWID is an
ordinary outcome rather than a fault.

```rust
use owid::{Owid, ParseStatus};

let result = Owid::from_base64("not base 64!");
match result {
    Ok(owid) => println!("read an OWID created by {}", owid.domain()),
    Err(error) => {
        // The reason is a named status, so nothing has to match on message
        // text, and no detail ever carries any part of the input.
        assert_eq!(error.status(), ParseStatus::InvalidBase64);
        println!("not an OWID because {error}");
    }
}
```

Create an OWID whose signature covers other OWIDs as well, as a processor
does when adding itself to a transaction. The same others, in the same
order, must be passed when verifying.

```rust
use owid::{Creator, Crypto, SignatureStatus};

let root = Creator::new("root.com", Crypto::new())
    .unwrap()
    .create_string("root")
    .unwrap();

let crypto = Crypto::new();
let processor = Creator::new("processor.com", crypto.clone()).unwrap();
let response = processor
    .create_bytes_with_others(b"response".to_vec(), &[&root])
    .unwrap();

// Verification must include the same others.
assert_eq!(
    response.verify_status_with_crypto(&crypto, &[&root]),
    SignatureStatus::Valid);
```

Verify an OWID by fetching the creator public key from the well known end
point. Requires the `fetch` feature. A key that cannot be fetched or read is
never reported as a signature that does not match.

```rust
use owid::{Owid, SignatureStatus};

fn check(encoded: &str) -> SignatureStatus {
    match Owid::from_base64(encoded) {
        Ok(owid) => owid.verify_status("https", &[]),
        Err(_) => SignatureStatus::VerificationError,
    }
}
```

Host the well known end points with any HTTP framework. Requires the
`endpoints` feature.

```rust
use owid::{endpoints, Creator};

fn responses(creator: &Creator) -> (String, String) {
    // GET /owid/api/v3/creator
    let creator_body =
        endpoints::creator_response(creator, "Example Org", "").unwrap();

    // GET /owid/api/v3/public-key?format=spki
    let key_body = endpoints::public_key_response(creator, "spki").unwrap();

    (creator_body, key_body)
}
```

## Interface

### Types

|Type|Description|
|-|-|
|`Owid`|The OWID, with its version, domain, date, payload and signature. Read only, and obtained only by reading a complete serialized OWID or from a `Creator` that creates and signs one.|
|`Creator`|Binds a domain to a signing key. Creates and signs OWIDs.|
|`Crypto`|Holds the ECDSA P-256 keys. Generates key pairs, imports and exports PEM, signs and verifies byte arrays.|
|`Configuration`|Domain and key PEM settings used to construct a `Creator`.|
|`Version`|The OWID version byte. Version 3 is current. Versions 1 and 2 are readable for compatibility.|
|`ParseError`, `ParseStatus`, `ParseDetail`|Why bytes are not an OWID. The status is the cross language name for the reason, and no detail ever carries any part of the input.|
|`SignatureStatus`|The outcome of asking whether a signature is genuine, keeping a signature that does not match apart from a check that could not be made.|
|`Error`|Errors from creating, signing, serializing and verifying.|

### Methods

|Method|Description|
|-|-|
|`Owid::from_base64`, `Owid::from_byte_array`|Read an OWID, answering with a `ParseError` where the bytes are not one. Base 64 is accepted with or without padding.|
|`Owid::as_base64`, `Owid::as_byte_array`|Serialize an OWID.|
|`Owid::version`, `domain`, `date`, `payload`, `signature`|Read the fields. The byte fields come back as read only views.|
|`Owid::payload_as_string`, `payload_as_printable`, `payload_as_base64`|The payload as UTF-8 text, hexadecimal, and base 64.|
|`Owid::age_minutes`|Complete minutes elapsed since creation.|
|`Owid::verify_with_crypto`, `verify_with_public_key`|Verify the signature, optionally with the other OWIDs that were signed together.|
|`Owid::verify_status_with_crypto`, `verify_status_with_public_key`|The same checks, answered with a `SignatureStatus`.|
|`Owid::verify`, `verify_status`|Verify by fetching the creator public key over HTTP (`fetch` feature).|
|`Creator::create_string`, `create_bytes`, `create_bytes_with_others`|Create and sign an OWID in one step. The creator sets the version, the domain and the date.|
|`Crypto::new`, `new_sign_only`, `new_verify_only`|Generate or import keys. Private keys are accepted in both PKCS#8 and SEC1 PEM forms.|
|`Crypto::public_key_pem`, `private_key_pem`|Export keys as PEM.|

## Data structure notes

The binary format is a one byte version, a null terminated domain, the date
as minutes since 2020-01-01 UTC in a little endian unsigned 32 bit integer
(two byte big endian hours for the deprecated version 1), the payload length
and payload, then the 64 byte ECDSA P-256 signature over the SHA-256 digest
of everything before it.

* The domain is at most 253 characters. RFC 1035 section 2.3.4 restricts a
  domain name to 255 octets in wire form, counting the length octet before
  each label and the octet for the root, so the presentation form stored
  here holds two characters fewer.
* String payloads are encoded as UTF-8.
* The deprecated version 1 date field stores a two byte big endian count of
  hours since the base date.
* `payload_as_printable` returns zero padded lower case hexadecimal.
* The marker `Owid::empty_to_buffer` writes is a single zero byte saying an
  optional OWID is absent. A marker is not an OWID, so reading one as a
  complete envelope reports `UnsupportedVersion`.
* Base 64 is accepted with or without padding. Output is always padded.
* Signatures are deterministic (RFC 6979). Verification accepts any valid
  ECDSA P-256 signature, whether produced deterministically or with a
  random nonce, because the verification algorithm is the same for both.

## Testing

The unit tests cover creation, signing, serialization, and verification
across all supported versions. The compatibility and interop suites include
externally produced fixtures, with byte exact round trips and verification
of signatures generated outside this library, proving that the wire format
and the signature verification are portable. `tests/parse_contract.rs`
holds the cross language status matrix, being the reasons a read reports
and the proof that an OWID cannot be held unsigned.

The examples in this file are documentation tests, so `cargo test
--all-features` compiles and runs them and they cannot quietly stop
working.

```bash
cargo test
cargo test --all-features
```

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.

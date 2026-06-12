![Open Web Id](https://github.com/SWAN-community/owid/raw/main/images/owl.128.pxls.100.dpi.png)

# Open Web Id (OWID) Rust

## Overview

Open Web Id (OWID) is an open source cryptographically secure shared web
identifier schema. This repository implements OWID in Rust.

Read the [OWID](https://github.com/SWAN-community/owid) project to learn more
about the concepts before looking into this implementation.

## Scope of this implementation

This library creates, signs, serializes, and verifies OWIDs. It provides the
same features as the [.NET](https://github.com/SWAN-community/owid-dotnet)
and [Go](https://github.com/SWAN-community/owid-go) implementations, allowing
for language specific differences.

The core crate performs no network access and compiles for WebAssembly
targets such as `wasm32-wasip1`, which makes it suitable for edge computing
environments. Two optional features extend it.

* `fetch` adds verification that retrieves the creator public key over HTTP
  from the well known end point and caches it. This mirrors the domain based
  verification in the .NET and Go implementations.
* `endpoints` adds framework agnostic helpers for hosting the well known end
  points that an OWID creator must serve.

The Go implementation additionally contains a complete creator service with
storage backends and registration pages. That is hosting infrastructure
rather than part of the library contract, so it is not reproduced here.

## Installation

Add the crate to `Cargo.toml`.

```toml
[dependencies]
owid = "0.1"
```

Enable the optional features as needed.

```toml
[dependencies]
owid = { version = "0.1", features = ["fetch", "endpoints"] }
```

## Usage

Create and sign an OWID, then verify it with the public key.

```rust
use owid::{Creator, Crypto, Owid};

// The creator operates a domain and holds the signing keys. Crypto::new
// generates a new ECDSA P-256 key pair. Keys can also be imported from PEM
// with Crypto::new_sign_only and Crypto::new_verify_only.
let crypto = Crypto::new();
let creator = Creator::new("example.com", crypto.clone())?;

// Create and sign an OWID with a payload.
let owid = creator.sign_string("Hello World")?;

// Serialize to base 64 for storage or transmission.
let encoded = owid.as_base64()?;

// Later, or elsewhere, decode and verify with the creator public key.
let copy = Owid::from_base64(&encoded)?;
let public_pem = crypto.public_key_pem()?;
assert!(copy.verify_with_public_key(&public_pem, &[])?);
```

Sign an OWID together with other OWIDs, as a processor does when adding
itself to a transaction. The same others, in the same order, must be passed
when verifying.

```rust
use owid::{Creator, Crypto, Owid};

let creator = Creator::new("processor.com", Crypto::new())?;

let root = Owid::from_base64("[signed OWID]")?;
let mut response = Owid {
    payload: b"response".to_vec(),
    ..Owid::default()
};
creator.sign_with_others(&mut response, &[&root])?;

// Verification must include the same others.
assert!(response.verify_with_crypto(creator.crypto(), &[&root])?);
```

Verify an OWID by fetching the creator public key from the well known end
point. Requires the `fetch` feature.

```rust
use owid::Owid;

let owid = Owid::from_base64("[signed OWID]")?;
let valid = owid.verify("https", &[])?;
```

Host the well known end points with any HTTP framework. Requires the
`endpoints` feature.

```rust
use owid::endpoints;

// GET /owid/api/v3/creator
let body = endpoints::creator_response(&creator, "Example Org", "")?;

// GET /owid/api/v3/public-key?format=spki
let body = endpoints::public_key_response(&creator, "spki")?;
```

## Interface

### Types

|Type|Description|
|-|-|
|`Owid`|The OWID structure with version, domain, date, payload, and signature fields. Parses from and serializes to bytes and base 64.|
|`Creator`|Binds a domain to a signing key. Creates and signs OWIDs.|
|`Crypto`|Holds the ECDSA P-256 keys. Generates key pairs, imports and exports PEM, signs and verifies byte arrays.|
|`Configuration`|Domain and key PEM settings used to construct a `Creator`.|
|`Version`|The OWID version byte. Version 3 is current. Versions 1 and 2 are readable for compatibility.|
|`Error`|All errors returned by the crate.|

### Methods

|Method|Description|
|-|-|
|`Owid::from_base64`, `Owid::from_byte_array`|Parse an OWID. Base 64 is accepted with or without padding.|
|`Owid::as_base64`, `Owid::as_byte_array`|Serialize a signed OWID.|
|`Owid::payload_as_string`, `payload_as_printable`, `payload_as_base64`|Payload accessors as UTF-8 text, hexadecimal, and base 64.|
|`Owid::age_minutes`|Complete minutes elapsed since creation.|
|`Owid::verify_with_crypto`, `verify_with_public_key`|Verify the signature, optionally with the other OWIDs that were signed together.|
|`Owid::verify`|Verify by fetching the creator public key over HTTP (`fetch` feature).|
|`Creator::sign`, `sign_with_others`, `sign_string`, `sign_bytes`|Create and sign OWIDs. Signing sets the domain and the date.|
|`Crypto::new`, `new_sign_only`, `new_verify_only`|Generate or import keys. Private keys are accepted in PKCS#8 and SEC1 PEM forms, matching the forms produced by the .NET and Go implementations.|
|`Crypto::public_key_pem`, `private_key_pem`|Export keys as PEM.|

## Data structure and language specific notes

The binary format is identical to the other implementations. One byte
version, null terminated domain, date as minutes since 2020-01-01 UTC in a
little endian unsigned 32 bit integer (two byte big endian hours for the
deprecated version 1), payload length and payload, then the 64 byte ECDSA
P-256 signature over the SHA-256 digest of everything before it.

* String payloads use UTF-8, the same as Go and JavaScript. The .NET
  implementation is ASCII only for its string convenience APIs.
* The deprecated version 1 date field follows the .NET reading of hours
  since the base date. The Go implementation read the same two bytes as
  days.
* `payload_as_printable` returns zero padded lower case hexadecimal. The
  exact hexadecimal formatting differs between every implementation.
* Signatures are deterministic (RFC 6979), unlike the randomized signatures
  produced by .NET and Go. Both kinds verify everywhere because the
  verification algorithm is the same.

## Testing

The tests port the canonical test matrix shared by the .NET, Go, and
JavaScript implementations. The compatibility suite parses the base 64
fixtures from the JavaScript test suite and asserts byte exact round trips,
proving the wire format matches the other languages. The interop suite
verifies fixtures signed by the Go and .NET implementations, proving that
verification works across languages and not just within this one.

```bash
cargo test
cargo test --all-features
```

## Related repositories

* [owid](https://github.com/SWAN-community/owid) defines the OWID
  specification and concepts.
* [owid-dotnet](https://github.com/SWAN-community/owid-dotnet) is the .NET
  implementation. It creates, signs and verifies OWIDs server side.
* [owid-go](https://github.com/SWAN-community/owid-go) is the Go
  implementation. It creates, signs and verifies OWIDs server side.
* [owid-js](https://github.com/SWAN-community/owid-js) is the JavaScript
  implementation. It verifies OWIDs in the browser.

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.

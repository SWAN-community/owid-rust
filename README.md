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
environments. Three optional features extend it.

* `fetch` adds domain based verification that retrieves the creator public
  key from the well known end point through a transport the caller supplies,
  and caches it. The fetch is asynchronous, needs no particular runtime and
  does not require a `Send` future, and the feature adds no dependency, so
  it builds for WebAssembly targets where the host provides HTTP.
* `reqwest-fetch` adds a ready made transport over asynchronous reqwest with
  rustls, which never follows a redirect, for hosts that have no HTTP of
  their own.
* `endpoints` adds framework agnostic helpers for hosting the well known end
  points that an OWID creator must serve.

## How an OWID comes into being

An OWID is only worth anything because it is signed, so this crate does not
let one exist in an unsigned state. There are exactly two ways an instance
reaches calling code.

1. `Owid::from_base64` or `Owid::from_byte_array` reads a complete
   serialized OWID, and `Owid::read_from_prefix` reads one from the front of
   a buffer carrying more after it. Data arriving from outside that is not
   an OWID is an ordinary outcome, so the answer is a `ParseError` naming
   the reason with a `ParseStatus`, and never anything raised.
2. `Creator::create` builds and signs one in a single step, owning the
   version, the domain, the date and the signature, while the caller
   supplies the payload, which may be anything that becomes bytes.

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
owid = { version = "2", features = ["reqwest-fetch", "endpoints"] }
```

Enable `fetch` on its own where the host provides HTTP, as it does on
`wasm32-wasip1`, and supply the transport.

```toml
[dependencies]
owid = { version = "2", features = ["fetch"] }
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
let owid = creator.create("Hello World").unwrap();

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
        // text, and no detail ever carries text from the input.
        assert_eq!(error.status(), ParseStatus::InvalidBase64);
        println!("not an OWID because {error}");
    }
}
```

Walk a buffer carrying one OWID after another. The framed read hands back
the bytes that follow the frame it read, which is what reading the next one
needs, and it says nothing about them, because they may be the next frame
rather than rubbish. A frame may also hold the one byte marker standing for
a node that is not there, which it steps over, handing back `None` so a
caller can tell an absent node from a malformed one.

```rust
use owid::{Creator, Crypto, Owid};

let creator = Creator::new("example.com", Crypto::new()).unwrap();
let mut buffer = Vec::new();
for payload in ["first", "second"] {
    creator.create(payload).unwrap().to_buffer(&mut buffer).unwrap();
}

let mut rest = buffer.as_slice();
let mut payloads = Vec::new();
while !rest.is_empty() {
    let (owid, remainder) = Owid::read_from_prefix(rest).unwrap();
    // None where the frame said the node is not there.
    if let Some(owid) = owid {
        payloads.push(owid.payload_as_string());
    }
    rest = remainder;
}
assert_eq!(payloads, ["first", "second"]);
```

The whole buffer read refuses that same buffer, because there a buffer holds
one OWID and nothing else could own the bytes after it. The two reads
otherwise report the same reasons, differing in three answers, all listed
under the data structure notes below.

Create an OWID whose signature covers other OWIDs as well, as a processor
does when adding itself to a transaction. The same others, in the same
order, must be passed when verifying.

```rust
use owid::{Creator, Crypto, SignatureStatus};

let root = Creator::new("root.com", Crypto::new())
    .unwrap()
    .create("root")
    .unwrap();

let crypto = Crypto::new();
let processor = Creator::new("processor.com", crypto.clone()).unwrap();
let response = processor
    .create_with_others(b"response".to_vec(), &[&root])
    .unwrap();

// Verification must include the same others.
assert_eq!(
    response.verify_status_with_crypto(&crypto, &[&root]),
    SignatureStatus::Valid);
```

Verify an OWID by fetching the creator public key from the well known end
point. Requires the `fetch` feature and a transport that implements
`PublicKeyFetch`. A key that cannot be fetched or read is never reported as
a signature that does not match.

The request carries the OWID's own date, counted in whole minutes from
2020-01-01, so a creator that rotates its key returns the key that was in
force when the OWID was signed rather than whichever key is current. Creators
commonly rotate weekly, so an undated request can only verify identifiers
signed since the most recent rotation. A creator that ignores the parameter
returns its current key, so every identifier it signed under an earlier key
reads as not matching, which is why a creator that rotates its key has to
honour the date.

Keys already fetched are held by creator, each against the span of minutes the
creator has confirmed it for. A key is in force from the start of its period
until the next key starts, so a key the creator answers with at two minutes was
in force at every minute between them, and an identifier dated inside a
confirmed span is verified without a request whichever minute it carries. One
dated outside every span is asked about, which widens the span when the same
key comes back. One dated within fifteen minutes of now, or later, is asked
about every time and never held, because a creator whose clock differs from
this one's may have read that minute as its present rather than as the minute
named. Live identifiers therefore cost one request per minute per creator, as
they always did, and older ones cost none. At most 1024 keys are held across
every creator before the cache is emptied and filled again, and a caller that
asks for a key while another caller is fetching it waits for that fetch rather
than starting a second. `clear_cache` empties what is held, which is how a long
running process drops a key it has learned it should no longer trust, after a
creator rotates its key following a compromise.

```text
GET https://[domain]/owid/api/v3/public-key?date=3510720&format=pkcs
```

Only a 200 is taken as the key. A redirect is never followed, because a key
from wherever a redirect points is not the creator's key, so the crate reads
any 3xx as the key being unavailable and a transport must hand the redirect
back rather than follow it. The `reqwest-fetch` feature provides
`ReqwestFetch`, which refuses redirects on its own account as well and waits
at most ten seconds for an answer. It holds a connection pool, so build one
and share it.

```rust
use owid::{Owid, PublicKeyFetch, ReqwestFetch, SignatureStatus};

async fn check(fetch: &dyn PublicKeyFetch, encoded: &str) -> SignatureStatus {
    match Owid::from_base64(encoded) {
        Ok(owid) => owid.verify_status(fetch, "https", &[]).await,
        Err(_) => SignatureStatus::VerificationError,
    }
}

let fetch = ReqwestFetch::new().unwrap();
```

Where the host provides HTTP, implement the transport over it. The future
it answers with is boxed and is not required to be `Send`, so a transport
tied to one thread works, and no async runtime is needed beyond whatever
drives the host.

```rust
use owid::{FetchResponse, LocalBoxFuture, PublicKeyFetch, Result};

struct HostFetch;

impl PublicKeyFetch for HostFetch {
    fn fetch<'a>(&'a self, url: &'a str) -> LocalBoxFuture<'a, Result<FetchResponse>> {
        Box::pin(async move {
            // Make the request without following a redirect, and hand back
            // the status and the body as they were answered.
            let (status, body) = host_get(url).await?;
            Ok(FetchResponse { status, body })
        })
    }
}
# async fn host_get(_url: &str) -> Result<(u16, String)> { Ok((404, String::new())) }
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
|`ParseError`, `ParseStatus`, `ParseDetail`|Why bytes are not an OWID, or are the marker for a node that is not there. The status is the cross language name for the reason. A detail carries counts, a fixed field name and the one version byte that was not recognised, so a log never receives the domain, the payload or any other text the sender chose.|
|`SignatureStatus`|The outcome of asking whether a signature is genuine, keeping a signature that does not match apart from a check that could not be made.|
|`Error`|Errors from creating, signing, serializing and verifying.|
|`PublicKeyFetch`, `FetchResponse`, `LocalBoxFuture`|The transport that makes the public key request for `Owid::verify`, what it hands back, and the boxed future it answers with, which is not required to be `Send` (`fetch` feature).|
|`ReqwestFetch`|The ready made transport over asynchronous reqwest with rustls, which never follows a redirect (`reqwest-fetch` feature).|
|`clear_cache`|Empties the held public keys, so the next verification asks the creator again (`fetch` feature).|

### Methods

|Method|Description|
|-|-|
|`Owid::from_base64`, `Owid::from_byte_array`|Read an OWID from a buffer that holds one, answering with a `ParseError` where the bytes are not one. Base 64 is accepted with or without padding.|
|`Owid::read_from_prefix`|Read one frame from the front of a buffer carrying more after it, returning what it held, which is `None` for the absent node marker, with the bytes that follow. Consumes nothing when it fails.|
|`Owid::as_base64`, `Owid::as_byte_array`|Serialize an OWID.|
|`Owid::to_buffer`, `Owid::empty_to_buffer`|Append an OWID, or the one byte marker for a node that is not there, to a buffer that carries a run of frames.|
|`Owid::version`, `domain`, `date`, `payload`, `signature`|Read the fields. The byte fields come back as read only views.|
|`Owid::payload_as_string`, `payload_as_printable`, `payload_as_base64`|The payload as UTF-8 text, hexadecimal, and base 64.|
|`Owid::age_minutes`|Complete minutes elapsed since creation.|
|`Owid::verify_with_crypto`, `verify_with_public_key`|Verify the signature, optionally with the other OWIDs that were signed together.|
|`Owid::verify_status_with_crypto`, `verify_status_with_public_key`|The same checks, answered with a `SignatureStatus`.|
|`Owid::verify`, `verify_status`|Verify by fetching the creator public key from the well known end point through a `PublicKeyFetch`, asynchronously (`fetch` feature).|
|`Creator::create`, `create_with_others`|Create and sign an OWID in one step, from anything that becomes bytes. The creator sets the version, the domain and the date.|
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
* The marker `Owid::empty_to_buffer` writes is a single zero byte saying a
  node is not there. No OWID is handed back for one on either read, because
  it carries no signature.
* The two reads differ in three answers, and agree everywhere else.
  * A whole buffer read requires the declared payload to leave exactly the
    signature, so a byte after it is a `ByteCountMismatch`. A framed read
    requires only that the payload and the signature are present and says
    nothing about what follows.
  * A frame whose declared payload runs past the bytes supplied is an
    `UnexpectedEnd`, being data that stopped early, so a caller reading a
    source that is still arriving can wait for more bytes rather than give
    up. `ByteCountMismatch` is only reachable on the whole buffer read,
    where every byte is present by definition.
  * A framed read steps over the marker and hands back `None` with the
    bytes after it, reporting `AbsentNode`. A whole buffer read reports
    `AbsentNode` as well, because a marker is a meaningful thing to find
    and not an unsupported version, but it has nothing to hand back.
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
working. The `fetch` feature is built for `wasm32-wasip1` as well, which is
the proof that verification through a host supplied transport needs nothing
the target does not have.

```bash
cargo test
cargo test --all-features
cargo build --no-default-features --features fetch --target wasm32-wasip1
```

## License

This project is licensed under the Apache License, Version 2.0. See the
[LICENSE](LICENSE) file for details.

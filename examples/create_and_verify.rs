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

//! Walks through the OWID lifecycle. Creating keys, signing a payload,
//! serializing, verifying, and observing that tampering breaks
//! verification.
//!
//! Run with `cargo run --example create_and_verify`.

use owid::{Creator, Crypto, Owid};

fn main() -> owid::Result<()> {
    // The creator operates a domain and holds the signing keys. The keys
    // would normally be loaded from secure storage using
    // Crypto::new_sign_only. Here a new pair is generated.
    let crypto = Crypto::new();
    let creator = Creator::new("example.com", crypto.clone())?;
    println!("Public key for example.com:");
    println!("{}", crypto.public_key_pem()?);

    // Create and sign an OWID with a payload. Creating and signing are one
    // step, so an OWID never exists without a signature.
    let owid = creator.create("Hello World")?;
    let encoded = owid.as_base64()?;
    println!("Signed OWID: {encoded}");

    // Anyone holding the public key can decode and verify it.
    let copy = Owid::from_base64(&encoded)?;
    println!(
        "Payload '{}' created by '{}' verifies: {}",
        copy.payload_as_string(),
        copy.domain(),
        copy.verify_with_crypto(&crypto)?
    );

    // Any change after signing breaks verification. An OWID is read only,
    // so tampering happens to the bytes, which is how it would reach a
    // verifier in practice.
    let mut bytes = copy.as_byte_array()?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let tampered = Owid::from_byte_array(&bytes)?;
    println!(
        "Tampered OWID verifies: {}",
        tampered.verify_with_crypto(&crypto)?
    );
    println!(
        "Tampered OWID signature status: {}",
        tampered.verify_status_with_crypto(&crypto)
    );

    Ok(())
}

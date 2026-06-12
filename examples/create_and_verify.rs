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
//! serializing, verifying, signing together with another OWID as a
//! processor in a transaction, and observing that tampering breaks
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

    // Create and sign an OWID with a payload.
    let owid = creator.sign_string("Hello World")?;
    let encoded = owid.as_base64()?;
    println!("Signed OWID: {encoded}");

    // Anyone holding the public key can decode and verify it.
    let copy = Owid::from_base64(&encoded)?;
    println!(
        "Payload '{}' created by '{}' verifies: {}",
        copy.payload_as_string(),
        copy.domain,
        copy.verify_with_crypto(&crypto, &[])?
    );

    // A processor receiving the OWID adds itself to the transaction by
    // signing its own OWID together with the one received.
    let processor_crypto = Crypto::new();
    let processor = Creator::new("processor.com", processor_crypto.clone())?;
    let mut response = Owid {
        payload: b"processed".to_vec(),
        ..Owid::default()
    };
    processor.sign_with_others(&mut response, &[&copy])?;
    println!(
        "Processor OWID verifies with the original: {}",
        response.verify_with_crypto(&processor_crypto, &[&copy])?
    );
    println!(
        "Processor OWID verifies without the original: {}",
        response.verify_with_crypto(&processor_crypto, &[])?
    );

    // Any change after signing breaks verification. OWIDs are immutable.
    let mut tampered = copy.clone();
    tampered.payload = b"Hello Worle".to_vec();
    println!(
        "Tampered OWID verifies: {}",
        tampered.verify_with_crypto(&crypto, &[])?
    );

    Ok(())
}

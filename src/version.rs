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

use crate::error::{Error, Result};

/// The byte version of an OWID. Always the first byte of the serialized
/// form.
///
/// Versions 1 and 2 were deprecated during development of the specification
/// because they used an insecure algorithm or an insufficiently precise time
/// indicator. They remain readable for compatibility with data created by
/// earlier implementations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum Version {
    /// Marker used to indicate an optional OWID that is not present.
    Empty = 0,
    /// Deprecated. Stored the date as a two byte big endian count of hours
    /// elapsed since the base date.
    Version1 = 1,
    /// Deprecated. Stored the date as a four byte little endian count of
    /// minutes elapsed since the base date.
    Version2 = 2,
    /// The current version. The wire format is identical to version 2.
    #[default]
    Version3 = 3,
}

impl Version {
    /// Returns the version as the byte written to the serialized form.
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Version::Empty),
            1 => Ok(Version::Version1),
            2 => Ok(Version::Version2),
            3 => Ok(Version::Version3),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

impl From<Version> for u8 {
    fn from(value: Version) -> Self {
        value.as_byte()
    }
}

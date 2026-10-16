//! Bounded opaque identifiers. None of these values are credentials or attestation.
//!
//! The ASCII-only grammar deliberately avoids Unicode normalization and visual
//! confusables until the canonical KeyRef URI protocol is specified (KM-03).

use core::fmt;

/// Upper bound (bytes) for provider instance, namespace, logical and version IDs.
pub const MAX_IDENTIFIER_BYTES: usize = 128;
/// Upper bound (bytes) for a native provider resource identifier.
pub const MAX_RESOURCE_BYTES: usize = 1024;

/// An invalid identifier, without retaining or displaying the rejected input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
    /// Identifier is empty.
    Empty,
    /// Identifier exceeds its documented byte bound.
    TooLong,
    /// Identifier contains unsupported characters or ambiguous formatting.
    InvalidCharacter,
    /// A credential-bearing field or URL userinfo was detected.
    CredentialInLocator,
    /// Resource URI contains a malformed percent encoding.
    InvalidEncoding,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Empty => "identifier is empty",
            Self::TooLong => "identifier is too long",
            Self::InvalidCharacter => "identifier has disallowed characters",
            Self::CredentialInLocator => "resource locator may contain credentials",
            Self::InvalidEncoding => "resource locator has invalid percent encoding",
        };
        f.write_str(message)
    }
}
impl std::error::Error for IdentityError {}

/// Restrict opaque identity labels to a deliberately small, unambiguous grammar.
fn validate_label(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(IdentityError::TooLong);
    }
    if value == "."
        || value == ".."
        || !value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_' | b'.'))
    {
        return Err(IdentityError::InvalidCharacter);
    }
    Ok(())
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(bytes: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(IdentityError::InvalidEncoding);
            }
            let hi = nibble(bytes[i + 1]).ok_or(IdentityError::InvalidEncoding)?;
            let lo = nibble(bytes[i + 2]).ok_or(IdentityError::InvalidEncoding)?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn suspicious_locator_field(bytes: &[u8]) -> bool {
    // Credential fields are forbidden at *every* encoding level. A public
    // pkcs11:token= label is deliberately NOT a credential (RFC 7512).
    const MARKERS: [&[u8]; 10] = [
        b"pin-value=",
        b"pin-source=",
        b"access_token=",
        b"bearer_token=",
        b"password=",
        b"secret=",
        b"access_key=",
        b"x-amz-security-token=",
        b"authorization=",
        b"client_secret=",
    ];
    MARKERS
        .iter()
        .any(|m| bytes.windows(m.len()).any(|window| window == *m))
}

fn validate_resource(value: &str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty);
    }
    if value.len() > MAX_RESOURCE_BYTES {
        return Err(IdentityError::TooLong);
    }
    if !value.is_ascii()
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control() || matches!(b, b'\\' | b'#'))
    {
        return Err(IdentityError::InvalidCharacter);
    }
    // Bare decimal native handles are not durable provider resource identities.
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(IdentityError::InvalidCharacter);
    }
    // RFC 3986 userinfo is not a safe stable key identifier. Fail closed.
    let lowercase = value.to_ascii_lowercase();
    if value.contains('@') || lowercase.starts_with("alias/") || lowercase.contains(":alias/") {
        return Err(IdentityError::CredentialInLocator);
    }
    let mut bytes = value.as_bytes().to_vec();
    for _ in 0..4 {
        bytes.make_ascii_lowercase();
        if bytes.contains(&b'@') || bytes.contains(&b'#') {
            return Err(IdentityError::CredentialInLocator);
        }
        if suspicious_locator_field(&bytes) {
            return Err(IdentityError::CredentialInLocator);
        }
        if !bytes.contains(&b'%') {
            return Ok(());
        }
        bytes = percent_decode(&bytes)?;
    }
    // Multiple nested encodings are never necessary in a normal provider ID.
    if bytes.contains(&b'%') {
        return Err(IdentityError::InvalidEncoding);
    }
    bytes.make_ascii_lowercase();
    if suspicious_locator_field(&bytes) {
        return Err(IdentityError::CredentialInLocator);
    }
    Ok(())
}

macro_rules! make_label {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
        pub struct $name(String);
        impl $name {
            /// Validate and construct a bounded ASCII identifier.
            pub fn parse(value: &str) -> Result<Self, IdentityError> {
                validate_label(value)?;
                Ok(Self(value.to_owned()))
            }
            /// Return the unambiguous identity string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
        impl TryFrom<&str> for $name {
            type Error = IdentityError;
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::parse(value)
            }
        }
    };
}

make_label!(
    ProviderInstanceId,
    "A host-registered provider adapter instance; not a provider brand."
);
make_label!(
    ProviderNamespace,
    "Authoritative host-supplied tenant, account, or partition namespace."
);
make_label!(
    LogicalKeyId,
    "Stable application key-group identity, distinct from any provider version."
);
make_label!(
    ProviderVersionId,
    "Provider-addressable key version; NOT proof of exact material revision."
);
make_label!(
    MaterialRevisionId,
    "Opaque material revision identifier; metadata alone does not mean selectable."
);

/// The library's key-version identifier means a provider-addressable version,
/// never an independently attested physical key-material revision.
pub type KeyVersionId = ProviderVersionId;

/// A validated, durable **candidate** native resource locator, never an alias
/// guarantee. An adapter must independently confirm stability and scope.
/// It cannot contain public-URI credential parameters or URL userinfo.
///
/// Native PKCS#11 object handles are never persistent key identities:
/// ```compile_fail
/// use keymesh::ProviderResourceId;
/// let ck_object_handle: usize = 42;
/// let _: ProviderResourceId = ck_object_handle;
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ProviderResourceId(String);
impl ProviderResourceId {
    /// Validate a bounded ASCII native resource locator. This does not resolve it.
    pub fn parse(value: &str) -> Result<Self, IdentityError> {
        validate_resource(value)?;
        Ok(Self(value.to_owned()))
    }
    /// Return the original opaque locator without normalization or rewriting.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Display for ProviderResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl TryFrom<&str> for ProviderResourceId {
    type Error = IdentityError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

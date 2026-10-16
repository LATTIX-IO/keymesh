//! Canonical, bounded KeyRef URI v1. Never represents authorization or a bearer capability.
//!
//! The URI grammar is defined in docs/specs/keyref-uri-v1.md. Identity labels
//! are deliberately ASCII-only in v1. The opaque native resource is encoded
//! as exactly one percent-encoded URI path segment, not treated as URI syntax.

use crate::binding::{KeyRef, KeySelector};
use crate::identity::{
    IdentityError, LogicalKeyId, MAX_RESOURCE_BYTES, MaterialRevisionId, ProviderInstanceId,
    ProviderNamespace, ProviderResourceId, ProviderVersionId,
};
use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;

/// Maximum length in bytes of a canonical KeyRef URI v1.
pub const MAX_KEY_REF_URI_BYTES: usize = 4096;

const PREFIX: &str = "keymesh://v1/";

/// Failure to parse a KeyRef URI; untrusted input is not retained or printed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyRefUriError {
    /// URI exceeds the bounded v1 representation.
    TooLong,
    /// Scheme, case, or explicit version authority is not supported.
    UnsupportedSchemeOrVersion,
    /// URI has missing, extra, or ambiguous path components.
    InvalidStructure,
    /// Percent encoding, raw reserved characters, or UTF-8 is invalid.
    InvalidEncoding,
    /// Input is well-formed but is not the unique canonical spelling.
    NonCanonical,
    /// Provider instance, tenant namespace, logical key or version is invalid.
    InvalidIdentity(IdentityError),
    /// Native provider resource did not pass the separate opaque-locator validator.
    InvalidResource(IdentityError),
}

impl fmt::Display for KeyRefUriError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::TooLong => "KeyRef URI exceeds the size limit",
            Self::UnsupportedSchemeOrVersion => "unsupported KeyRef URI scheme or version",
            Self::InvalidStructure => "invalid KeyRef URI structure",
            Self::InvalidEncoding => "invalid KeyRef URI encoding",
            Self::NonCanonical => "noncanonical KeyRef URI representation",
            Self::InvalidIdentity(_) => "invalid KeyRef URI identity field",
            Self::InvalidResource(_) => "invalid KeyRef URI native resource field",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for KeyRefUriError {}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(b - b'A' + 10),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// Encode a validated opaque native locator into one canonical URI component.
/// Encoding is byte-preserving (no case folding, Unicode normalization or host lookup).
fn encode_resource(f: &mut fmt::Formatter<'_>, native: &ProviderResourceId) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in native.as_str().bytes() {
        if is_unreserved(b) {
            f.write_char(char::from(b))?;
        } else {
            f.write_char('%')?;
            f.write_char(char::from(HEX[usize::from(b >> 4)]))?;
            f.write_char(char::from(HEX[usize::from(b & 0x0F)]))?;
        }
    }
    Ok(())
}

/// Decode exactly one path component; forbid double interpretation of URI
/// separators. The returned locator is separately validated by ProviderResourceId.
fn decode_resource(encoded: &str) -> Result<ProviderResourceId, KeyRefUriError> {
    if encoded.is_empty() {
        return Err(KeyRefUriError::InvalidStructure);
    }
    if encoded.len() > MAX_RESOURCE_BYTES * 3 {
        return Err(KeyRefUriError::TooLong);
    }
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(KeyRefUriError::InvalidEncoding);
                }
                let hi = hex(bytes[i + 1]).ok_or(KeyRefUriError::InvalidEncoding)?;
                let lo = hex(bytes[i + 2]).ok_or(KeyRefUriError::InvalidEncoding)?;
                decoded.push((hi << 4) | lo);
                i += 3;
            }
            b if is_unreserved(b) => {
                decoded.push(b);
                i += 1;
            }
            _ => return Err(KeyRefUriError::InvalidEncoding),
        }
        if decoded.len() > MAX_RESOURCE_BYTES {
            return Err(KeyRefUriError::TooLong);
        }
    }
    let native = String::from_utf8(decoded).map_err(|_| KeyRefUriError::InvalidEncoding)?;
    let resource = ProviderResourceId::parse(&native).map_err(KeyRefUriError::InvalidResource)?;
    Ok(resource)
}

impl fmt::Display for KeyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{PREFIX}{}/{}/{}/",
            self.provider(),
            self.namespace(),
            self.logical_key()
        )?;
        match self.selector() {
            KeySelector::Active => f.write_str("active"),
            KeySelector::Latest => f.write_str("latest"),
            KeySelector::StableResource(resource) => {
                f.write_str("resource/")?;
                encode_resource(f, resource)
            }
            KeySelector::ExactProviderVersion { resource, version } => {
                f.write_str("version/")?;
                encode_resource(f, resource)?;
                write!(f, "/{version}")
            }
            KeySelector::ExactMaterialRevision {
                resource,
                version,
                revision,
            } => {
                f.write_str("material/")?;
                encode_resource(f, resource)?;
                write!(f, "/{version}/{revision}")
            }
        }
    }
}

impl FromStr for KeyRef {
    type Err = KeyRefUriError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        if input.len() > MAX_KEY_REF_URI_BYTES {
            return Err(KeyRefUriError::TooLong);
        }
        if !input.starts_with(PREFIX) {
            return Err(KeyRefUriError::UnsupportedSchemeOrVersion);
        }
        // V1 uses only ASCII. Scope/authority labels never undergo normalization.
        // A literal ?/#/@/backslash is never valid in a serialized reference.
        if !input.is_ascii()
            || input
                .bytes()
                .any(|b| b.is_ascii_control() || matches!(b, b'?' | b'#' | b'@' | b'\\'))
        {
            return Err(KeyRefUriError::InvalidEncoding);
        }
        let mut segments = input[PREFIX.len()..].split('/');
        let provider =
            ProviderInstanceId::parse(segments.next().ok_or(KeyRefUriError::InvalidStructure)?)
                .map_err(KeyRefUriError::InvalidIdentity)?;
        let namespace =
            ProviderNamespace::parse(segments.next().ok_or(KeyRefUriError::InvalidStructure)?)
                .map_err(KeyRefUriError::InvalidIdentity)?;
        let key = LogicalKeyId::parse(segments.next().ok_or(KeyRefUriError::InvalidStructure)?)
            .map_err(KeyRefUriError::InvalidIdentity)?;
        let selector_name = segments.next().ok_or(KeyRefUriError::InvalidStructure)?;
        let selector = match selector_name {
            "active" => KeySelector::Active,
            "latest" => KeySelector::Latest,
            "resource" => {
                let resource =
                    decode_resource(segments.next().ok_or(KeyRefUriError::InvalidStructure)?)?;
                KeySelector::StableResource(resource)
            }
            "version" => {
                let resource =
                    decode_resource(segments.next().ok_or(KeyRefUriError::InvalidStructure)?)?;
                let version = ProviderVersionId::parse(
                    segments.next().ok_or(KeyRefUriError::InvalidStructure)?,
                )
                .map_err(KeyRefUriError::InvalidIdentity)?;
                KeySelector::ExactProviderVersion { resource, version }
            }
            "material" => {
                let resource =
                    decode_resource(segments.next().ok_or(KeyRefUriError::InvalidStructure)?)?;
                let version = ProviderVersionId::parse(
                    segments.next().ok_or(KeyRefUriError::InvalidStructure)?,
                )
                .map_err(KeyRefUriError::InvalidIdentity)?;
                let revision = MaterialRevisionId::parse(
                    segments.next().ok_or(KeyRefUriError::InvalidStructure)?,
                )
                .map_err(KeyRefUriError::InvalidIdentity)?;
                KeySelector::ExactMaterialRevision {
                    resource,
                    version,
                    revision,
                }
            }
            _ => return Err(KeyRefUriError::InvalidStructure),
        };
        if segments.next().is_some() {
            return Err(KeyRefUriError::InvalidStructure);
        }
        let result = KeyRef::new(provider, namespace, key, selector);
        // Require the single canonical form, including uppercase hex escapes,
        // no percent-escaped identity labels and no superfluous escapes.
        if result.to_string() != input {
            return Err(KeyRefUriError::NonCanonical);
        }
        Ok(result)
    }
}

//! Move-only, bounded secret ownership with drop-time zeroization.
//!
//! This is a Rust-owned memory boundary, not locked memory, an OS credential
//! vault, hardware erasure, or a guarantee about upstream/downstream copies.
//! KM-05 still denies raw KeyMaterial inputs before any provider dispatch.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Hard limit for an individual in-memory secret or provider credential.
/// Applications with larger secrets require a separately reviewed contract.
pub const MAX_SECRET_BYTES: usize = 65_536;

/// Static input failure, with no secret bytes, values or variable messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretError {
    /// Empty secret material is not accepted by this general-purpose wrapper.
    Empty,
    /// Length or reserved capacity exceeds the configured bound.
    TooLarge,
}
impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "empty secret material",
            Self::TooLarge => "secret material exceeds permitted storage bound",
        })
    }
}
impl std::error::Error for SecretError {}

/// Owned, bounded sensitive bytes. Deliberately **not** Clone, Copy,
/// Serialize, Deserialize, AsRef, Deref or Display. Debug is always redacted.
///
/// Construct by MOVING an existing Vec; accepted input is not copied.
/// On invalid input, the transferred Vec is zeroized before returning error.
/// On Drop, RustCrypto's Zeroize wipes the Vec's owned backing capacity,
/// including spare bytes, before deallocation.
///
/// This cannot erase earlier copies, stack/register spills, swap, crash
/// dumps, externally retained aliases, device buffers or FFI allocations.
///
/// # Compile-time non-exposure contracts
///
/// No implicit copies:
///
/// ```compile_fail
/// use keymesh::SecretBytes;
/// let secret = SecretBytes::from_vec(vec![7, 8]).unwrap();
/// let _copy = secret.clone();
/// ```
///
/// No plain text formatting:
///
/// ```compile_fail
/// use keymesh::SecretBytes;
/// let secret = SecretBytes::from_vec(vec![7, 8]).unwrap();
/// println!("{}", secret);
/// ```
///
/// No implicit raw slice conversion:
///
/// ```compile_fail
/// use keymesh::SecretBytes;
/// let secret = SecretBytes::from_vec(vec![7, 8]).unwrap();
/// let bytes: &[u8] = secret.as_ref();
/// ```
///
/// No accidental serde serialization:
///
/// ```compile_fail
/// use keymesh::SecretBytes;
/// let secret = SecretBytes::from_vec(vec![7, 8]).unwrap();
/// let _ = serde_json::to_string(&secret).unwrap();
/// ```
#[must_use = "secret owner must be retained only as long as needed"]
pub struct SecretBytes {
    bytes: Vec<u8>,
}
impl SecretBytes {
    /// Move and validate a Vec without copying accepted secret bytes.
    /// Rejected input is zeroized, including excess reserved capacity.
    pub fn from_vec(mut bytes: Vec<u8>) -> Result<Self, SecretError> {
        if bytes.is_empty() {
            bytes.zeroize();
            return Err(SecretError::Empty);
        }
        if bytes.len() > MAX_SECRET_BYTES || bytes.capacity() > MAX_SECRET_BYTES {
            bytes.zeroize();
            return Err(SecretError::TooLarge);
        }
        Ok(Self { bytes })
    }

    /// Number of owned bytes (metadata only, not an export operation).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether this allocation has been explicitly erased.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Explicitly wipe the owned allocation, including spare capacity. Once
    /// erased, this wrapper cannot be refilled or reused as a valid secret.
    pub fn erase(&mut self) {
        self.bytes.zeroize();
    }

    /// Invoke a deliberate, synchronous, narrowly scoped plaintext consumer.
    ///
    /// There is deliberately no unrestricted AsRef or Deref implementation.
    /// The callback cannot return a borrowed slice through this API, but
    /// hostile callback code can still copy its input to an external buffer.
    /// Only call a **trusted** adapter that enforces KM-05/KM-06 authorizations.
    /// Never log, panic-format, serialize or cache the supplied slice.
    pub fn with_exposed(&self, consumer: impl FnOnce(&[u8])) {
        consumer(self.bytes.as_slice());
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}
impl ZeroizeOnDrop for SecretBytes {}
impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

/// Distinct owned secret type for key material, NOT an operation-input
/// fallback. KM-05 still denies OperationInput::KeyMaterial before dispatch.
///
/// No implicit Clone, Copy, Display, Serialize, Deserialize, AsRef or Deref.
///
/// ```compile_fail
/// use keymesh::KeyMaterial;
/// let material = KeyMaterial::from_vec(vec![0x42; 32]).unwrap();
/// let _leak = serde_json::to_string(&material).unwrap();
/// ```
///
/// No implicit bypass of KM-05's raw-key dispatch guard:
///
/// ```compile_fail
/// use keymesh::{KeyMaterial, OperationInput};
/// let key = KeyMaterial::from_vec(vec![0x42; 32]).unwrap();
/// let _input = OperationInput::KeyMaterial(&key);
/// ```
#[must_use = "key material remains sensitive until erased"]
pub struct KeyMaterial(SecretBytes);
impl KeyMaterial {
    /// Convert an existing bounded nonempty secret without duplicating bytes.
    /// An already-erased buffer is rejected and dropped (not reactivated).
    pub fn new(secret: SecretBytes) -> Result<Self, SecretError> {
        if secret.is_empty() {
            return Err(SecretError::Empty);
        }
        Ok(Self(secret))
    }

    /// Move in raw key bytes and enforce the same limits as SecretBytes.
    pub fn from_vec(bytes: Vec<u8>) -> Result<Self, SecretError> {
        SecretBytes::from_vec(bytes).map(Self)
    }

    /// Size only; no secret data is released.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this material was erased.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Erase the owned key material before normal drop.
    pub fn erase(&mut self) {
        self.0.erase();
    }

    /// Controlled exposure to an audited, trusted host callback.
    /// Does not make KM-05 raw-key dispatch available.
    pub fn with_exposed(&self, consumer: impl FnOnce(&[u8])) {
        self.0.with_exposed(consumer);
    }
}
impl fmt::Debug for KeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeyMaterial(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepted_vec_moves_without_a_second_allocation() {
        let bytes = vec![1, 3, 5, 7, 9];
        let pointer = bytes.as_ptr();
        let secret = SecretBytes::from_vec(bytes).unwrap_or_else(|e| panic!("{e}"));
        secret.with_exposed(|exposed| {
            assert_eq!(exposed.as_ptr(), pointer);
            assert_eq!(exposed, [1, 3, 5, 7, 9]);
        });
    }

    #[test]
    fn explicit_erase_is_idempotent_and_leaves_no_readable_bytes() {
        let mut secret = SecretBytes::from_vec(vec![0x7B; 32]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(secret.len(), 32);
        secret.erase();
        assert!(secret.is_empty());
        secret.erase();
        secret.with_exposed(|bytes| assert!(bytes.is_empty()));

        let mut key = KeyMaterial::from_vec(vec![0x55; 48]).unwrap_or_else(|e| panic!("{e}"));
        key.erase();
        assert!(key.is_empty());
    }

    #[test]
    fn rejected_empty_oversized_and_excess_capacity_are_bounded() {
        assert!(matches!(
            SecretBytes::from_vec(vec![]),
            Err(SecretError::Empty)
        ));
        assert!(matches!(
            SecretBytes::from_vec(vec![0xA5; MAX_SECRET_BYTES + 1]),
            Err(SecretError::TooLarge)
        ));
        let mut oversized_allocation = Vec::with_capacity(MAX_SECRET_BYTES + 1);
        oversized_allocation.extend_from_slice(&[1, 2, 3, 4]);
        assert!(matches!(
            SecretBytes::from_vec(oversized_allocation),
            Err(SecretError::TooLarge)
        ));
        assert_eq!(
            SecretBytes::from_vec(vec![0x43; MAX_SECRET_BYTES])
                .unwrap_or_else(|e| panic!("{e}"))
                .len(),
            MAX_SECRET_BYTES
        );
    }

    #[test]
    fn key_material_cannot_reactivate_erased_allocation() {
        let mut owner = SecretBytes::from_vec(vec![0x44; 32]).unwrap_or_else(|e| panic!("{e}"));
        owner.erase();
        assert!(matches!(KeyMaterial::new(owner), Err(SecretError::Empty)));
    }

    #[test]
    fn error_debug_and_formatting_are_static_and_redacted() {
        let secret =
            SecretBytes::from_vec(b"never-in-logs".to_vec()).unwrap_or_else(|e| panic!("{e}"));
        let key = KeyMaterial::from_vec(b"private-key-material".to_vec())
            .unwrap_or_else(|e| panic!("{e}"));
        let full = format!(
            "{secret:?} {key:?} {} {:?}",
            SecretError::TooLarge,
            SecretError::Empty
        );
        assert!(!full.contains("never-in-logs"));
        assert!(!full.contains("private-key-material"));
        assert!(full.contains("<redacted>"));
    }
}

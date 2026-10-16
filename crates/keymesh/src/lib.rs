//! Provider-neutral key identity and pre-dispatch binding contracts.
//!
//! This initial API does **not** perform cryptographic operations or
//! authenticate callers. It validates identifiers and proposed bindings. See
//! `THREAT_MODEL.md` and ADR-0001/0002 in the repository for the trust model.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod binding;
mod identity;

pub use binding::{
    BindingAssurance, BindingError, BoundKey, DispatchTarget, HostScope, KeyRef, KeySelector,
    RequiredAssurance, ResolvedKey, preflight_bind,
};
pub use identity::{
    IdentityError, KeyVersionId, LogicalKeyId, MAX_IDENTIFIER_BYTES, MAX_RESOURCE_BYTES,
    MaterialRevisionId, ProviderInstanceId, ProviderNamespace, ProviderResourceId,
    ProviderVersionId,
};

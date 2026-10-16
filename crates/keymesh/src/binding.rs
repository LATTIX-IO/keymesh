//! Provider-neutral, fail-closed *pre-dispatch* identity and assurance checks.
//!
//! This module does not contact a provider or attest its metadata. A provider
//! adapter must supply authoritative resolution from its own credential and
//! authorization boundary, and dispatch using the returned `BoundKey` target.

use crate::identity::{
    LogicalKeyId, MaterialRevisionId, ProviderInstanceId, ProviderNamespace, ProviderResourceId,
    ProviderVersionId,
};
use core::fmt;

/// A key selector is an input requirement, not proof of which key was used.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeySelector {
    /// The provider-specific active logical version; must be resolved before dispatch.
    Active,
    /// The provider-specific latest logical version; must be resolved before dispatch.
    Latest,
    /// A specified stable native resource, not a mutable alias.
    StableResource(ProviderResourceId),
    /// A specified provider-addressable version of a resource.
    ExactProviderVersion {
        /// The expected durable resource.
        resource: ProviderResourceId,
        /// The expected provider version.
        version: ProviderVersionId,
    },
    /// A caller-addressable material revision that the provider guarantees it can select.
    ExactMaterialRevision {
        /// The expected durable resource.
        resource: ProviderResourceId,
        /// The expected provider version.
        version: ProviderVersionId,
        /// The expected cryptographic material revision.
        revision: MaterialRevisionId,
    },
}

/// Immutable logical key reference. Credentials and caller authorization are
/// deliberately excluded; a KeyRef is not a capability token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRef {
    provider: ProviderInstanceId,
    namespace: ProviderNamespace,
    logical_key: LogicalKeyId,
    selector: KeySelector,
}
impl KeyRef {
    /// Build a scope-qualified logical reference; does not authorize it.
    pub fn new(
        provider: ProviderInstanceId,
        namespace: ProviderNamespace,
        logical_key: LogicalKeyId,
        selector: KeySelector,
    ) -> Self {
        Self {
            provider,
            namespace,
            logical_key,
            selector,
        }
    }
    /// Requested provider instance.
    pub fn provider(&self) -> &ProviderInstanceId {
        &self.provider
    }
    /// Requested namespace, not proof of authenticated tenant identity.
    pub fn namespace(&self) -> &ProviderNamespace {
        &self.namespace
    }
    /// Requested logical key.
    pub fn logical_key(&self) -> &LogicalKeyId {
        &self.logical_key
    }
    /// Requested key selector.
    pub fn selector(&self) -> &KeySelector {
        &self.selector
    }
}

/// Provider and namespace fixed by the caller's *authenticated host* context.
/// Creating this token performs no IAM authentication; the host must create it
/// only after validating its identity, tenant and configured provider scope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostScope {
    provider: ProviderInstanceId,
    namespace: ProviderNamespace,
}
impl HostScope {
    /// Wrap a previously authenticated/authorized provider namespace mapping.
    pub fn new(provider: ProviderInstanceId, namespace: ProviderNamespace) -> Self {
        Self {
            provider,
            namespace,
        }
    }
    /// The host-authorized provider instance.
    pub fn provider(&self) -> &ProviderInstanceId {
        &self.provider
    }
    /// The host-authorized namespace.
    pub fn namespace(&self) -> &ProviderNamespace {
        &self.namespace
    }
}

/// Only concrete, explicitly specified dispatch targets can pass preflight.
/// There is no alias or opaque native object-handle variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchTarget {
    /// A stable provider resource ID, which may rotate material beneath it.
    StableResource(ProviderResourceId),
    /// A concrete provider-addressable version; actual material is not independently attested.
    ProviderVersion {
        /// The stable resource.
        resource: ProviderResourceId,
        /// The selectable version.
        version: ProviderVersionId,
    },
    /// An explicitly selectable material revision for the supported provider operation.
    /// Adapters must prove *actual selectability*; rotation-history metadata is inadequate.
    MaterialVersion {
        /// The stable resource.
        resource: ProviderResourceId,
        /// The provider version.
        version: ProviderVersionId,
        /// The caller-addressable material revision.
        revision: MaterialRevisionId,
    },
}
impl DispatchTarget {
    /// Stable native resource ID to pass directly to provider dispatch.
    pub fn resource(&self) -> &ProviderResourceId {
        match self {
            Self::StableResource(id) => id,
            Self::ProviderVersion { resource, .. } | Self::MaterialVersion { resource, .. } => {
                resource
            }
        }
    }
    /// Provider-addressable version when dispatch is bound to one.
    pub fn provider_version(&self) -> Option<&ProviderVersionId> {
        match self {
            Self::ProviderVersion { version, .. } | Self::MaterialVersion { version, .. } => {
                Some(version)
            }
            Self::StableResource(_) => None,
        }
    }
    /// Selectable material revision, if supported; NOT observed-only metadata.
    pub fn selected_material_revision(&self) -> Option<&MaterialRevisionId> {
        match self {
            Self::MaterialVersion { revision, .. } => Some(revision),
            _ => None,
        }
    }
    /// Claimed provider binding level, to be verified by the adapter for each operation.
    pub fn assurance(&self) -> BindingAssurance {
        match self {
            Self::StableResource(_) => BindingAssurance::StableResourceBound,
            Self::ProviderVersion { .. } => BindingAssurance::ProviderVersionBound,
            Self::MaterialVersion { .. } => BindingAssurance::MaterialVersionBound,
        }
    }
}

/// Qualitative guarantees for the operation's actual dispatch target, not
/// intrinsic properties of a KMS brand or of a stable resource name.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum BindingAssurance {
    /// Provider key resource was pinned; underlying key material may rotate.
    StableResourceBound,
    /// A provider-addressable version was pinned; physical material unverified.
    ProviderVersionBound,
    /// Specific selectable cryptographic material revision was pinned.
    MaterialVersionBound,
}

/// The minimum permissible binding guarantee, evaluated without fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredAssurance {
    /// Bind a stable provider resource, never an alias.
    StableResource,
    /// Bind a provider-addressable version of a stable resource.
    ProviderVersion,
    /// Bind a caller-addressable material revision, not merely observe one.
    MaterialVersion,
}
impl RequiredAssurance {
    fn minimum(self) -> BindingAssurance {
        match self {
            Self::StableResource => BindingAssurance::StableResourceBound,
            Self::ProviderVersion => BindingAssurance::ProviderVersionBound,
            Self::MaterialVersion => BindingAssurance::MaterialVersionBound,
        }
    }
}

/// Provider resolution proposal. Constructing this from a string or provider
/// response does not certify that a provider really implements the target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedKey {
    provider: ProviderInstanceId,
    namespace: ProviderNamespace,
    logical_key: LogicalKeyId,
    target: DispatchTarget,
    observed_material_revision: Option<MaterialRevisionId>,
}
impl ResolvedKey {
    /// Create a provider-specific resolution proposal; never pass an unresolved alias.
    pub fn new(
        provider: ProviderInstanceId,
        namespace: ProviderNamespace,
        logical_key: LogicalKeyId,
        target: DispatchTarget,
    ) -> Self {
        Self {
            provider,
            namespace,
            logical_key,
            target,
            observed_material_revision: None,
        }
    }
    /// Attach observational provider metadata; does NOT upgrade dispatch assurance.
    pub fn with_observed_material_revision(mut self, observed: MaterialRevisionId) -> Self {
        self.observed_material_revision = Some(observed);
        self
    }
    /// The resolved native dispatch target, never an alias.
    pub fn dispatch_target(&self) -> &DispatchTarget {
        &self.target
    }
    /// Any provider-reported material revision observed separately from selection.
    pub fn observed_material_revision(&self) -> Option<&MaterialRevisionId> {
        self.observed_material_revision.as_ref()
    }
}

/// Scope and binding error. Invalid values are not copied into error messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    /// Requested provider was not authorized by host scope or matched resolution.
    ProviderMismatch,
    /// Requested namespace did not match host authority or resolution.
    NamespaceMismatch,
    /// Logical key differs from provider-resolved key.
    LogicalKeyMismatch,
    /// Provider returned or selected a different stable resource.
    ResourceMismatch,
    /// Provider version does not match an explicit version requirement.
    VersionMismatch,
    /// Material revision does not match the exact expected revision.
    MaterialRevisionMismatch,
    /// Provider cannot satisfy the hard binding guarantee.
    UnsupportedVersionAssurance,
}
impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ProviderMismatch => "provider identity mismatch",
            Self::NamespaceMismatch => "authorized namespace mismatch",
            Self::LogicalKeyMismatch => "logical key mismatch",
            Self::ResourceMismatch => "stable key resource mismatch",
            Self::VersionMismatch => "provider version mismatch",
            Self::MaterialRevisionMismatch => "key material revision mismatch",
            Self::UnsupportedVersionAssurance => "provider cannot guarantee required key binding",
        };
        f.write_str(message)
    }
}
impl std::error::Error for BindingError {}

/// A validated read-only binding for subsequent provider dispatch. It does not
/// prove authorization, independently attest material, or execute a provider
/// operation. The adapter must use exactly its `dispatch_target()` as provided.
#[derive(Debug)]
pub struct BoundKey<'a> {
    resolved: &'a ResolvedKey,
}
impl<'a> BoundKey<'a> {
    /// Concrete native dispatch target; no aliases or provider auto-selection.
    pub fn dispatch_target(&self) -> &'a DispatchTarget {
        &self.resolved.target
    }
    /// Provider-reported assurance level of this target.
    pub fn assurance(&self) -> BindingAssurance {
        self.resolved.target.assurance()
    }
    /// Provider instance bound by preflight.
    pub fn provider(&self) -> &ProviderInstanceId {
        &self.resolved.provider
    }
    /// Authorized namespace bound by preflight.
    pub fn namespace(&self) -> &ProviderNamespace {
        &self.resolved.namespace
    }
    /// Logical key bound by preflight.
    pub fn logical_key(&self) -> &LogicalKeyId {
        &self.resolved.logical_key
    }
}

/// Validate a proposed resolution against host-approved scope, requested key,
/// exact selectors and required assurance, **before** dispatch occurs.
///
/// No alias fallback, namespace rewrite, or material-revision inference occurs.
/// Adapters must actually dispatch to `BoundKey::dispatch_target()`; until a
/// provider adapter enforces that contract, this is preflight validation only.
///
/// # Examples
///
/// ```
/// use keymesh::{preflight_bind, BindingAssurance, DispatchTarget, HostScope, KeyRef,
///     KeySelector, LogicalKeyId, ProviderInstanceId, ProviderNamespace, ProviderResourceId,
///     RequiredAssurance, ResolvedKey};
/// let provider = ProviderInstanceId::parse("local").unwrap_or_else(|_| unreachable!());
/// let namespace = ProviderNamespace::parse("tenant-a").unwrap_or_else(|_| unreachable!());
/// let key = LogicalKeyId::parse("billing").unwrap_or_else(|_| unreachable!());
/// let resource = ProviderResourceId::parse("software:billing:1").unwrap_or_else(|_| unreachable!());
/// let host = HostScope::new(provider.clone(), namespace.clone());
/// let reference = KeyRef::new(provider.clone(), namespace.clone(), key.clone(),
///     KeySelector::StableResource(resource.clone()));
/// let resolved = ResolvedKey::new(provider, namespace, key, DispatchTarget::StableResource(resource));
/// let bound = preflight_bind(&reference, &host, &resolved, RequiredAssurance::StableResource)
///     .unwrap_or_else(|_| unreachable!());
/// assert_eq!(bound.assurance(), BindingAssurance::StableResourceBound);
/// ```
pub fn preflight_bind<'a>(
    reference: &KeyRef,
    authorized: &HostScope,
    resolved: &'a ResolvedKey,
    required: RequiredAssurance,
) -> Result<BoundKey<'a>, BindingError> {
    if reference.provider != authorized.provider || resolved.provider != authorized.provider {
        return Err(BindingError::ProviderMismatch);
    }
    if reference.namespace != authorized.namespace || resolved.namespace != authorized.namespace {
        return Err(BindingError::NamespaceMismatch);
    }
    if reference.logical_key != resolved.logical_key {
        return Err(BindingError::LogicalKeyMismatch);
    }
    let target = &resolved.target;
    if target.assurance() < required.minimum() {
        return Err(BindingError::UnsupportedVersionAssurance);
    }
    match &reference.selector {
        KeySelector::Active | KeySelector::Latest => {}
        KeySelector::StableResource(resource) => {
            if target.resource() != resource {
                return Err(BindingError::ResourceMismatch);
            }
        }
        KeySelector::ExactProviderVersion { resource, version } => {
            if target.resource() != resource {
                return Err(BindingError::ResourceMismatch);
            }
            match target.provider_version() {
                Some(actual) if actual == version => {}
                Some(_) => return Err(BindingError::VersionMismatch),
                None => return Err(BindingError::UnsupportedVersionAssurance),
            }
        }
        KeySelector::ExactMaterialRevision {
            resource,
            version,
            revision,
        } => {
            if target.resource() != resource {
                return Err(BindingError::ResourceMismatch);
            }
            match target.provider_version() {
                Some(actual) if actual == version => {}
                Some(_) => return Err(BindingError::VersionMismatch),
                None => return Err(BindingError::UnsupportedVersionAssurance),
            }
            match target.selected_material_revision() {
                Some(actual) if actual == revision => {}
                Some(_) => return Err(BindingError::MaterialRevisionMismatch),
                None => return Err(BindingError::UnsupportedVersionAssurance),
            }
        }
    }
    Ok(BoundKey { resolved })
}

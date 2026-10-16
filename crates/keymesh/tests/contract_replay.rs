//! Generated replay of KM-01's identity/version contract on actual Rust preflight.
use keymesh::{
    DispatchTarget, HostScope, IdentityError, KeyRef, KeySelector, LogicalKeyId,
    MaterialRevisionId, ProviderInstanceId, ProviderNamespace, ProviderResourceId,
    ProviderVersionId, RequiredAssurance, ResolvedKey, preflight_bind,
};

struct Fixture {
    id: &'static str,
    req_provider: Option<&'static str>,
    req_namespace: Option<&'static str>,
    req_logical: Option<&'static str>,
    req_resource: Option<&'static str>,
    req_binding: Option<&'static str>,
    req_version: Option<&'static str>,
    req_material: Option<&'static str>,
    selector: Option<&'static str>,
    bound_provider: Option<&'static str>,
    bound_namespace: Option<&'static str>,
    bound_logical: Option<&'static str>,
    bound_resource: Option<&'static str>,
    dispatch_kind: Option<&'static str>,
    dispatch_version: Option<&'static str>,
    dispatch_material: Option<&'static str>,
    observed_material: Option<&'static str>,
    expected: bool,
}

const CASES: &[Fixture] = &include!("generated_km02_contract.inc");

fn label<T>(value: &str, parse: fn(&str) -> Result<T, IdentityError>) -> T {
    parse(value).unwrap_or_else(|_| panic!("invalid canonical fixture identifier"))
}

#[test]
fn km01_identity_version_contract_replay() {
    for case in CASES {
        let p = label(
            case.req_provider.unwrap_or_default(),
            ProviderInstanceId::parse,
        );
        let ns = label(
            case.req_namespace.unwrap_or_default(),
            ProviderNamespace::parse,
        );
        let key = label(case.req_logical.unwrap_or_default(), LogicalKeyId::parse);
        let resource = label(
            case.req_resource.unwrap_or_default(),
            ProviderResourceId::parse,
        );
        let selector = match case.selector {
            Some("active") => KeySelector::Active,
            Some("resource") => KeySelector::StableResource(resource),
            Some("version") => KeySelector::ExactProviderVersion {
                resource,
                version: label(
                    case.req_version.unwrap_or_default(),
                    ProviderVersionId::parse,
                ),
            },
            Some("material") => KeySelector::ExactMaterialRevision {
                resource,
                version: label(
                    case.req_version.unwrap_or_default(),
                    ProviderVersionId::parse,
                ),
                revision: label(
                    case.req_material.unwrap_or_default(),
                    MaterialRevisionId::parse,
                ),
            },
            _ => panic!("unsupported fixture selector"),
        };
        let wanted = KeyRef::new(p.clone(), ns.clone(), key, selector);
        let scope = HostScope::new(p, ns);
        let actual_resource = label(
            case.bound_resource.unwrap_or_default(),
            ProviderResourceId::parse,
        );
        let target = match case.dispatch_kind {
            Some("stable_resource") => DispatchTarget::StableResource(actual_resource),
            Some("provider_version") => DispatchTarget::ProviderVersion {
                resource: actual_resource,
                version: label(
                    case.dispatch_version.unwrap_or_default(),
                    ProviderVersionId::parse,
                ),
            },
            Some("material_version") => DispatchTarget::MaterialVersion {
                resource: actual_resource,
                version: label(
                    case.dispatch_version.unwrap_or_default(),
                    ProviderVersionId::parse,
                ),
                revision: label(
                    case.dispatch_material.unwrap_or_default(),
                    MaterialRevisionId::parse,
                ),
            },
            _ => panic!("unsupported fixture dispatch"),
        };
        let mut actual = ResolvedKey::new(
            label(
                case.bound_provider.unwrap_or_default(),
                ProviderInstanceId::parse,
            ),
            label(
                case.bound_namespace.unwrap_or_default(),
                ProviderNamespace::parse,
            ),
            label(case.bound_logical.unwrap_or_default(), LogicalKeyId::parse),
            target,
        );
        if let Some(revision) = case.observed_material {
            actual =
                actual.with_observed_material_revision(label(revision, MaterialRevisionId::parse));
        }
        let required = match case.req_binding {
            Some("stable_resource") => RequiredAssurance::StableResource,
            Some("provider_version") => RequiredAssurance::ProviderVersion,
            Some("material_version") => RequiredAssurance::MaterialVersion,
            _ => panic!("unsupported fixture requirement"),
        };
        assert_eq!(
            preflight_bind(&wanted, &scope, &actual, required).is_ok(),
            case.expected,
            "KM-01 fixture {} differs from KM-02 preflight",
            case.id
        );
    }
}

//! Demonstration of type-safe, pre-dispatch key identity checking (no cryptography).
use keymesh::{
    DispatchTarget, HostScope, KeyRef, KeySelector, LogicalKeyId, ProviderInstanceId,
    ProviderNamespace, ProviderResourceId, RequiredAssurance, ResolvedKey, preflight_bind,
};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let p = ProviderInstanceId::parse("reference")?;
    let ns = ProviderNamespace::parse("tenant-a")?;
    let k = LogicalKeyId::parse("signing")?;
    let r = ProviderResourceId::parse("software:signing:1")?;
    let scope = HostScope::new(p.clone(), ns.clone());
    let wanted = KeyRef::new(
        p.clone(),
        ns.clone(),
        k.clone(),
        KeySelector::StableResource(r.clone()),
    );
    let resolved = ResolvedKey::new(p, ns, k, DispatchTarget::StableResource(r));
    let bound = preflight_bind(
        &wanted,
        &scope,
        &resolved,
        RequiredAssurance::StableResource,
    )?;
    println!("pre-dispatch contract satisfied: {:?}", bound.assurance());
    // This is not evidence of provider authentication, key operation execution or HSM protection.
    Ok(())
}

//! KeyRef URI v1 round-trip plus pre-dispatch scope validation (no cryptography).
use keymesh::{
    DispatchTarget, HostScope, KeyRef, LogicalKeyId, ProviderInstanceId, ProviderNamespace,
    ProviderResourceId, RequiredAssurance, ResolvedKey, preflight_bind,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let textual =
        "keymesh://v1/software-local/tenant-a/customer-data/resource/software%3Acustomer-data%3A42";
    let reference: KeyRef = textual.parse()?;
    assert_eq!(reference.to_string(), textual);

    // Authentication belongs to the host; only a host-validated mapping may
    // construct the operational authority in an actual application.
    let authorized = HostScope::new(
        ProviderInstanceId::parse("software-local")?,
        ProviderNamespace::parse("tenant-a")?,
    );
    let resolution = ResolvedKey::new(
        ProviderInstanceId::parse("software-local")?,
        ProviderNamespace::parse("tenant-a")?,
        LogicalKeyId::parse("customer-data")?,
        DispatchTarget::StableResource(ProviderResourceId::parse("software:customer-data:42")?),
    );
    let target = preflight_bind(
        &reference,
        &authorized,
        &resolution,
        RequiredAssurance::StableResource,
    )?;
    println!("canonical KeyRef: {textual}");
    println!(
        "validated pre-dispatch target: {}",
        target.dispatch_target().resource()
    );
    Ok(())
}

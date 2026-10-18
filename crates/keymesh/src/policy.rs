//! KM-10 additive policy-decision contract.
//! No provider dispatch takes place until policy requirements and any
//! explicitly configured audit sink have accepted the exact bound request.

use crate::{
    AlgorithmProfile, BindingAssurance, CorrelationId, HostValidatedCapabilities, KeyProvider,
    OperationCompletion, OperationRequest, PolicyContext, PolicyGate, PolicyVerdict,
    ProtectionClass, ProviderError, ProviderErrorKind, ProviderFuture, VersionRequirement,
    execute_checked,
};
use core::fmt;

/// Host-supplied requirements that must not be weakened by provider selection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PolicyRequirements {
    /// Optional exact approved algorithm and parameter profile.
    pub algorithm: Option<AlgorithmProfile>,
    /// Minimum exact target-binding strength.
    pub min_version: Option<VersionRequirement>,
    /// Optional host-verified custody requirement; TEE never satisfies HSM.
    pub protection: Option<ProtectionClass>,
}
impl PolicyRequirements {
    fn permits(&self, context: &PolicyContext<'_>, host: &HostValidatedCapabilities) -> bool {
        if self
            .algorithm
            .as_ref()
            .is_some_and(|p| p != &context.intent.profile)
        {
            return false;
        }
        if let Some(required) = self.min_version {
            let actual = context.resolved.dispatch_target().assurance();
            let minimum = match required {
                VersionRequirement::StableResource => BindingAssurance::StableResourceBound,
                VersionRequirement::ProviderVersion => BindingAssurance::ProviderVersionBound,
                VersionRequirement::MaterialRevision => BindingAssurance::MaterialVersionBound,
            };
            if actual < minimum {
                return false;
            }
        }
        if let Some(required) = self.protection {
            // A provider's self-description is not a substitute for trusted
            // host corroboration. Unknown never satisfies a custody policy.
            if required == ProtectionClass::Unknown
                || host.protection != Some(required)
                || host.scope.as_ref() != Some(context.scope)
            {
                return false;
            }
        }
        true
    }
}

/// Evaluation result from the trusted host, with no implicit permit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    /// Explicit host evaluator verdict.
    pub verdict: PolicyVerdict,
    /// Additional non-downgradable constraints.
    pub requirements: PolicyRequirements,
    /// Optional bounded, non-secret policy revision label.
    pub policy_revision: Option<CorrelationId>,
}

/// Redacted pre-dispatch evidence. Not signed, durable, or an attestation.
pub struct PolicyDecisionEvidence<'a> {
    /// Exact scope and bounded operation metadata are available via this view.
    pub context: &'a PolicyContext<'a>,
    /// Correlation supplied by the authenticated host.
    pub correlation: &'a CorrelationId,
    /// Trusted evaluator result before requirement enforcement.
    pub decision: &'a PolicyDecision,
    /// Whether requirements were satisfied in addition to a Permit verdict.
    pub requirements_satisfied: bool,
}
impl fmt::Debug for PolicyDecisionEvidence<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PolicyDecisionEvidence(<redacted>)")
    }
}

/// Trusted host adapter returning typed decisions; no plaintext input is passed.
pub trait DecisionPolicyGate: Send + Sync {
    /// Evaluate a fully resolved, checked pre-dispatch request.
    fn decide<'a>(&'a self, context: &'a PolicyContext<'_>) -> ProviderFuture<'a, PolicyDecision>;
}

/// Optional synchronous pre-dispatch record sink. Failures prevent dispatch.
/// The sink must not block indefinitely and must handle its own secure storage.
pub trait PolicyAuditSink: Send + Sync {
    /// Record the requested decision and requirement result without key bytes.
    fn record(&self, evidence: &PolicyDecisionEvidence<'_>) -> Result<(), ProviderError>;
}

struct DecisionAdapter<'a> {
    evaluator: &'a dyn DecisionPolicyGate,
    sink: Option<&'a dyn PolicyAuditSink>,
    host: &'a HostValidatedCapabilities,
    correlation: &'a CorrelationId,
}
impl PolicyGate for DecisionAdapter<'_> {
    fn evaluate<'a>(&'a self, context: &'a PolicyContext<'_>) -> ProviderFuture<'a, PolicyVerdict> {
        Box::pin(async move {
            let decision = self.evaluator.decide(context).await?;
            let satisfied = decision.requirements.permits(context, self.host);
            if let Some(sink) = self.sink {
                let evidence = PolicyDecisionEvidence {
                    context,
                    correlation: self.correlation,
                    decision: &decision,
                    requirements_satisfied: satisfied,
                };
                // A sink failure is never converted to Permit, even if the
                // policy itself allowed the operation.
                if sink.record(&evidence).is_err() {
                    return Err(ProviderError::not_dispatched(
                        ProviderErrorKind::PolicyIndeterminate,
                    ));
                }
            }
            if !satisfied {
                return Ok(PolicyVerdict::Deny);
            }
            Ok(decision.verdict)
        })
    }
}

/// Run the existing KM-05 gateway with explicit policy requirements and an
/// optional fail-closed audit boundary. This API does not weaken or replace
/// `execute_checked`; both require trusted host policy.
pub async fn execute_checked_with_decision(
    provider: &dyn KeyProvider,
    evaluator: &dyn DecisionPolicyGate,
    sink: Option<&dyn PolicyAuditSink>,
    request: OperationRequest<'_>,
) -> Result<OperationCompletion, ProviderError> {
    let gate = DecisionAdapter {
        evaluator,
        sink,
        host: request.host_assurance,
        correlation: request.correlation,
    };
    execute_checked(provider, &gate, request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_debug_always_redacts() {
        assert_eq!(
            format!("{:?}", PolicyRequirements::default()),
            "PolicyRequirements { algorithm: None, min_version: None, protection: None }"
        );
    }

    #[test]
    fn default_policy_requirements_cannot_authorize_by_themselves() {
        let r = PolicyRequirements::default();
        assert!(r.algorithm.is_none());
        assert!(r.min_version.is_none());
        assert!(r.protection.is_none());
        // Only DecisionPolicyGate may issue a Permit; defaults are not a decision.
    }
}

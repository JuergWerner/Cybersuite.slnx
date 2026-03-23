namespace Cybersuite.ProviderHost;

/// <summary>
/// Stable reason codes used by the provider-host lifecycle journal and logs.
/// Codes are intentionally short, machine-friendly, and secret-free.
/// </summary>
public static class ProviderHostReasonCodes
{
    public const string TrustRejected = "trust_rejected";
    public const string ExperimentalProviderRejected = "experimental_provider_rejected";
    public const string LaunchContextRejected = "launch_context_rejected";
    public const string LaunchFailed = "launch_failed";
    public const string LaunchDeadlineExceeded = "launch_deadline_exceeded";
    public const string HandshakeFailed = "handshake_failed";
    public const string HandshakeDeadlineExceeded = "handshake_deadline_exceeded";
    public const string CapabilityNegotiationFailed = "capability_negotiation_failed";
    public const string CapabilityDeadlineExceeded = "capability_deadline_exceeded";
    public const string ManifestHelloMismatch = "manifest_hello_mismatch";
    public const string ProviderIdMismatch = "provider_id_mismatch";
    public const string ExpectedProviderMismatch = "expected_provider_mismatch";
    public const string ExpectedBuildHashMismatch = "expected_build_hash_mismatch";
    public const string PolicyHashMismatch = "policy_hash_mismatch";
    public const string CapabilityHashMismatch = "capability_hash_mismatch";
    public const string CapabilityBudgetExceeded = "capability_budget_exceeded";
    public const string CapabilityDecodeFailed = "capability_decode_failed";
    public const string BoundaryRequirementRejected = "boundary_requirement_rejected";
    public const string ReferenceProviderRejectedOutsideDev = "reference_provider_rejected_outside_dev";
    public const string ProvenanceBundleMissing = "provenance_bundle_missing";
    public const string ProvenanceVerificationFailed = "provenance_verification_failed";
    public const string ReleaseBundleMissing = "release_bundle_missing";
    public const string ReleaseVerificationFailed = "release_verification_failed";
    public const string ManifestIsolationEnvelopeMismatch = "manifest_isolation_envelope_mismatch";
    public const string AttestationRequiredMissing = "attestation_required_missing";
    public const string AttestationVerificationFailed = "attestation_verification_failed";
    public const string HostDisposed = "host_disposed";
}

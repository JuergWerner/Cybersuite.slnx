namespace Cybersuite.Policy;

/// <summary>
/// Abstraction for verifying the cryptographic signature of a policy document.
/// Implementations are injected via <see cref="PolicyLoadOptions.SignatureVerifier"/>.
/// The verifier receives the canonical (signature-excluded) policy bytes and the
/// <see cref="PolicySignatureEnvelope"/> extracted from the JSON. This allows the
/// policy layer to remain algorithm-agnostic while still enforcing signature integrity
/// in production profiles [ARC-401].
/// </summary>
public interface IPolicySignatureVerifier
{
    bool Verify(
        ReadOnlySpan<byte> canonicalPolicyBytes,
        PolicySignatureEnvelope signature,
        PolicySignatureVerificationOptions options,
        out string? failureReason);
}
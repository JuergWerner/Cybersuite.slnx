namespace Cybersuite.Policy;

/// <summary>
/// Algorithms supported for policy document signature verification.
/// The policy signature protects the canonical bytes of the policy JSON, ensuring
/// tamper detection and provenance verification before the policy is trusted [ARC-401].
/// </summary>
public enum PolicySignatureAlgorithm
{
    RsaPssSha384 = 0,
    EcdsaP384Sha384 = 1
}
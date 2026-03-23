namespace Cybersuite.Abstractions;

/// <summary>
/// Execution profile that governs security gates throughout the Cybersuite pipeline.
/// Referenced in [ARC-010] (Trust Boundaries) and [POL-000] (Policy Integrity).
/// 
/// The profile influences multiple security-critical decisions:
/// - <b>Dev:</b> Relaxed — signature verification and provider allowlists may be optional.
///   Experimental providers are permitted. Useful for local development and testing.
/// - <b>Staging:</b> Intermediate — allowlists recommended, signature verification encouraged.
///   Experimental providers may still be permitted depending on policy.
/// - <b>Prod:</b> Strict — policy signature verification required, provider allowlist must be
///   non-empty (fail-closed), experimental providers rejected. This is the default posture
///   defined in <see cref="Policy"/> load options.
/// 
/// The profile is also transmitted in the OOP handshake (<see cref="OopProtocol.Handshake.ClientHello"/>)
/// so providers can adjust their own security posture accordingly.
/// </summary>
public enum ExecutionProfile
{
    /// <summary>Development profile: relaxed security gates for local testing.</summary>
    Dev = 0,

    /// <summary>Staging profile: intermediate enforcement, pre-production validation.</summary>
    Staging = 1,

    /// <summary>Production profile: full enforcement — fail-closed on missing signatures, allowlists, or FIPS violations.</summary>
    Prod = 2
}
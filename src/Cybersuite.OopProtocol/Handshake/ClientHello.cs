using System;
using Cybersuite.Abstractions;

namespace Cybersuite.OopProtocol.Handshake;

/// <summary>
/// OPP handshake message sent from the Core (ProviderHost) to the Provider process.
/// Binds the active policy hash, execution profile, and FIPS/experimental flags into
/// the handshake transcript so both parties agree on the security posture for the session.
///
/// <b>Security invariants:</b>
/// <list type="bullet">
///   <item><see cref="Nonce"/> is a 32-byte CSPRNG freshness token preventing replay attacks.</item>
///   <item><see cref="PolicyHashSha384"/> is the SHA-384 digest of the canonicalized policy, binding the session to a specific policy version.</item>
///   <item><see cref="Profile"/> communicates the enforcement level (Dev/Staging/Prod) so the provider can adjust its own gates.</item>
/// </list>
/// </summary>
public sealed class ClientHello
{
    /// <summary>OPP protocol version offered by the host (must match ProviderHello for v1).</summary>
    public ProtocolVersion Version { get; }

    /// <summary>32-byte cryptographic nonce for handshake freshness.</summary>
    public ReadOnlyMemory<byte> Nonce { get; }

    /// <summary>SHA-384 digest of the canonicalized policy bytes, binding the session to a specific policy snapshot.</summary>
    public ReadOnlyMemory<byte> PolicyHashSha384 { get; }

    /// <summary>Active execution profile (Dev / Staging / Prod) governing security gate strictness.</summary>
    public ExecutionProfile Profile { get; }

    /// <summary>Whether the compliance posture requires FIPS-approved algorithms only.</summary>
    public bool FipsRequired { get; }

    /// <summary>Whether experimental (non-Stable) algorithm capabilities are permitted.</summary>
    public bool ExperimentalAllowed { get; }

    /// <summary>Optional tenant scope identifier for multi-tenant deployments. Null for single-tenant.</summary>
    public string? TenantId { get; }

    /// <summary>Optional expected provider ID for identity pre-verification. Null if not constrained.</summary>
    public string? ExpectedProviderId { get; }

    /// <summary>Optional expected build hash (SHA-256 hex) for entrypoint integrity pre-verification. Null if not constrained.</summary>
    public string? ExpectedBuildHash { get; }

    public ClientHello(
        ProtocolVersion version,
        ReadOnlySpan<byte> nonce32,
        ReadOnlySpan<byte> policyHashSha384,
        ExecutionProfile profile,
        bool fipsRequired,
        bool experimentalAllowed,
        string? tenantId,
        string? expectedProviderId,
        string? expectedBuildHash)
    {
        if (nonce32.Length != OopConstants.NonceSizeBytes)
            throw new ArgumentException("Nonce must be 32 bytes.", nameof(nonce32));

        if (policyHashSha384.Length != OopConstants.Sha384SizeBytes)
            throw new ArgumentException("PolicyHashSha384 must be 48 bytes (SHA-384).", nameof(policyHashSha384));

        Version = version;

        var n = new byte[OopConstants.NonceSizeBytes];
        nonce32.CopyTo(n);
        Nonce = n;

        var ph = new byte[OopConstants.Sha384SizeBytes];
        policyHashSha384.CopyTo(ph);
        PolicyHashSha384 = ph;

        Profile = profile;
        FipsRequired = fipsRequired;
        ExperimentalAllowed = experimentalAllowed;

        TenantId = string.IsNullOrWhiteSpace(tenantId) ? null : tenantId;
        ExpectedProviderId = string.IsNullOrWhiteSpace(expectedProviderId) ? null : expectedProviderId;
        ExpectedBuildHash = string.IsNullOrWhiteSpace(expectedBuildHash) ? null : expectedBuildHash;
    }

    public byte[] ToCanonicalBytes() => OopWireFormat.EncodeClientHello(this);
}
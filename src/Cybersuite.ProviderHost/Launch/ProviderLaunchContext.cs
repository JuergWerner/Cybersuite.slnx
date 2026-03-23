using System;
using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Launch;

/// <summary>
/// Canonical, host-derived launch context passed to launch handlers.
/// Eliminates hidden environment defaults and carries the real runtime posture.
/// </summary>
public sealed record ProviderLaunchContext(
    ExecutionProfile Profile,
    ProviderSecurityClass TargetSecurityClass,
    RequiredBoundaryClass RequiredBoundaryClass,
    OopTransportBudget TransportBudget,
    bool EnableNetworkAccess,
    ImmutableArray<byte> BoundPolicyHashSha384,
    ProviderId? ExpectedProviderId,
    ImmutableArray<byte>? ExpectedBuildHashSha256)
{
    public void Validate()
    {
        if (TransportBudget is null)
            throw new ArgumentNullException(nameof(TransportBudget));

        TransportBudget.Validate();

        if (BoundPolicyHashSha384.IsDefaultOrEmpty || BoundPolicyHashSha384.Length != 48)
            throw new ArgumentException("BoundPolicyHashSha384 must be 48 bytes (SHA-384).", nameof(BoundPolicyHashSha384));

        if (ExpectedBuildHashSha256 is { } expectedBuildHash &&
            !expectedBuildHash.IsDefaultOrEmpty &&
            expectedBuildHash.Length != 32)
        {
            throw new ArgumentException("ExpectedBuildHashSha256 must be 32 bytes (SHA-256) when present.", nameof(ExpectedBuildHashSha256));
        }
    }
}

using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Stage 5 keeps transport and capability canonicalization separated.
/// A decoder turns provider-returned canonical capability bytes into a CapabilitySnapshot
/// and validates the claimed SHA-384 hash.
/// </summary>
public interface ICapabilitySnapshotDecoder
{
    CapabilitySnapshot Decode(
        ProviderIdentity identity,
        ReadOnlySpan<byte> capabilityCanonicalBytes,
        ReadOnlySpan<byte> claimedCapabilityHashSha384);
}
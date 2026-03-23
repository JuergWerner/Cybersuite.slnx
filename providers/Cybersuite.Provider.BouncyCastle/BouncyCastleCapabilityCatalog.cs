using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Composite capability catalog.
/// In Dev/reference mode it exposes the stable classical subset plus the experimental PQC subset.
/// In Wave 4 production-isolated mode it can expose the classical subset only so runtime claims stay truthful.
/// </summary>
public static class BouncyCastleCapabilityCatalog
{
    public static CapabilitySnapshot CreateSnapshot(ProviderIdentity identity, bool includeExperimentalAlgorithms = true)
    {
        ProviderId provider = identity.ProviderId;

        ImmutableArray<AlgorithmDescriptor> classical = BouncyCastleClassicalStableCapabilityCatalog.CreateAlgorithms(provider);
        ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile> artifactProfiles =
            BouncyCastleClassicalStableCapabilityCatalog.CreateArtifactProfiles();

        if (!includeExperimentalAlgorithms)
        {
            return CapabilitySnapshot.Create(
                identity,
                classical,
                artifactProfiles);
        }

        ImmutableArray<AlgorithmDescriptor> pqc = BouncyCastlePqcExperimentalCapabilityCatalog.CreateAlgorithms(provider);

        var algorithmsBuilder = ImmutableArray.CreateBuilder<AlgorithmDescriptor>(classical.Length + pqc.Length);
        algorithmsBuilder.AddRange(classical);
        algorithmsBuilder.AddRange(pqc);

        artifactProfiles = artifactProfiles.SetItems(BouncyCastlePqcExperimentalCapabilityCatalog.CreateArtifactProfiles());

        return CapabilitySnapshot.Create(
            identity,
            algorithmsBuilder.ToImmutable(),
            artifactProfiles);
    }
}

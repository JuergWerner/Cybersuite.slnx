using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

internal static class BouncyCastleClassicalStableCapabilityCatalog
{
    public static ImmutableArray<AlgorithmDescriptor> CreateAlgorithms(ProviderId provider)
    {
        return ImmutableArray.Create(
            new AlgorithmDescriptor(
                id: new AlgorithmId("ECDH-P384-KEM"),
                provider: provider,
                category: AlgorithmCategory.KeyEncapsulation,
                securityMode: AlgorithmSecurityMode.Classical,
                strength: new SecurityStrength(192),
                isFipsApproved: false),

            new AlgorithmDescriptor(
                id: new AlgorithmId("ECDSA-P384"),
                provider: provider,
                category: AlgorithmCategory.Signature,
                securityMode: AlgorithmSecurityMode.Classical,
                strength: new SecurityStrength(192),
                isFipsApproved: false),

            new AlgorithmDescriptor(
                id: new AlgorithmId("AES-256-GCM"),
                provider: provider,
                category: AlgorithmCategory.SymmetricAead,
                securityMode: AlgorithmSecurityMode.Classical,
                strength: new SecurityStrength(256),
                isFipsApproved: false),

            new AlgorithmDescriptor(
                id: new AlgorithmId("HKDF-SHA384"),
                provider: provider,
                category: AlgorithmCategory.KeyDerivation,
                securityMode: AlgorithmSecurityMode.Classical,
                strength: new SecurityStrength(192),
                isFipsApproved: false),

            new AlgorithmDescriptor(
                id: new AlgorithmId("SHA-384"),
                provider: provider,
                category: AlgorithmCategory.Hash,
                securityMode: AlgorithmSecurityMode.Classical,
                strength: new SecurityStrength(192),
                isFipsApproved: false)
        );
    }

    public static ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile> CreateArtifactProfiles()
    {
        return ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile>.Empty
            .Add(
                new AlgorithmId("ECDH-P384-KEM"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 97,
                    privateKeyBytes: 0,
                    ciphertextBytes: 97,
                    sharedSecretBytes: 48,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative))
            .Add(
                new AlgorithmId("ECDSA-P384"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 97,
                    privateKeyBytes: 0,
                    signatureBytes: 96,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative))
            .Add(
                new AlgorithmId("AES-256-GCM"),
                new CapabilityArtifactProfile(
                    symmetricKeyBytes: 32,
                    nonceBytes: 12,
                    tagBytes: 16))
            .Add(
                new AlgorithmId("HKDF-SHA384"),
                new CapabilityArtifactProfile(
                    sharedSecretBytes: 32,
                    symmetricKeyBytes: 32))
            .Add(
                new AlgorithmId("SHA-384"),
                CapabilityArtifactProfile.Empty);
    }
}
using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

internal static class BouncyCastlePqcExperimentalCapabilityCatalog
{
    public static ImmutableArray<AlgorithmDescriptor> CreateAlgorithms(ProviderId provider)
    {
        return ImmutableArray.Create(
            new AlgorithmDescriptor(
                id: new AlgorithmId("ML-KEM-512"),
                provider: provider,
                category: AlgorithmCategory.KeyEncapsulation,
                securityMode: AlgorithmSecurityMode.Pqc,
                strength: new SecurityStrength(128),
                isFipsApproved: false,
                parameterSetId: new AlgorithmParameterSetId("ML-KEM-512"),
                operationalMaturity: AlgorithmOperationalMaturity.Experimental,
                encodingProfile: AlgorithmEncodingProfile.ProviderNative),

            new AlgorithmDescriptor(
                id: new AlgorithmId("ML-KEM-768"),
                provider: provider,
                category: AlgorithmCategory.KeyEncapsulation,
                securityMode: AlgorithmSecurityMode.Pqc,
                strength: new SecurityStrength(192),
                isFipsApproved: false,
                parameterSetId: new AlgorithmParameterSetId("ML-KEM-768"),
                operationalMaturity: AlgorithmOperationalMaturity.Experimental,
                encodingProfile: AlgorithmEncodingProfile.ProviderNative),

            new AlgorithmDescriptor(
                id: new AlgorithmId("ML-KEM-1024"),
                provider: provider,
                category: AlgorithmCategory.KeyEncapsulation,
                securityMode: AlgorithmSecurityMode.Pqc,
                strength: new SecurityStrength(256),
                isFipsApproved: false,
                parameterSetId: new AlgorithmParameterSetId("ML-KEM-1024"),
                operationalMaturity: AlgorithmOperationalMaturity.Experimental,
                encodingProfile: AlgorithmEncodingProfile.ProviderNative),

            new AlgorithmDescriptor(
                id: new AlgorithmId("ML-DSA-44"),
                provider: provider,
                category: AlgorithmCategory.Signature,
                securityMode: AlgorithmSecurityMode.Pqc,
                strength: new SecurityStrength(128),
                isFipsApproved: false,
                parameterSetId: new AlgorithmParameterSetId("ML-DSA-44"),
                operationalMaturity: AlgorithmOperationalMaturity.Experimental,
                encodingProfile: AlgorithmEncodingProfile.ProviderNative),

            new AlgorithmDescriptor(
                id: new AlgorithmId("ML-DSA-65"),
                provider: provider,
                category: AlgorithmCategory.Signature,
                securityMode: AlgorithmSecurityMode.Pqc,
                strength: new SecurityStrength(192),
                isFipsApproved: false,
                parameterSetId: new AlgorithmParameterSetId("ML-DSA-65"),
                operationalMaturity: AlgorithmOperationalMaturity.Experimental,
                encodingProfile: AlgorithmEncodingProfile.ProviderNative),

            new AlgorithmDescriptor(
                id: new AlgorithmId("ML-DSA-87"),
                provider: provider,
                category: AlgorithmCategory.Signature,
                securityMode: AlgorithmSecurityMode.Pqc,
                strength: new SecurityStrength(256),
                isFipsApproved: false,
                parameterSetId: new AlgorithmParameterSetId("ML-DSA-87"),
                operationalMaturity: AlgorithmOperationalMaturity.Experimental,
                encodingProfile: AlgorithmEncodingProfile.ProviderNative)
        );
    }

    public static ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile> CreateArtifactProfiles()
    {
        return ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile>.Empty
            .Add(
                new AlgorithmId("ML-KEM-512"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 800,
                    ciphertextBytes: 768,
                    sharedSecretBytes: 32,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative))
            .Add(
                new AlgorithmId("ML-KEM-768"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 1184,
                    ciphertextBytes: 1088,
                    sharedSecretBytes: 32,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative))
            .Add(
                new AlgorithmId("ML-KEM-1024"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 1568,
                    ciphertextBytes: 1568,
                    sharedSecretBytes: 32,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative))
            .Add(
                new AlgorithmId("ML-DSA-44"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 1312,
                    signatureBytes: 2420,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative))
            .Add(
                new AlgorithmId("ML-DSA-65"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 1952,
                    signatureBytes: 3309,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative))
            .Add(
                new AlgorithmId("ML-DSA-87"),
                new CapabilityArtifactProfile(
                    publicKeyBytes: 2592,
                    signatureBytes: 4627,
                    publicKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative,
                    privateKeyEncodingProfile: AlgorithmEncodingProfile.ProviderNative));
    }
}
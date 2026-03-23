using Cybersuite.Abstractions;

namespace Cybersuite.ProviderModel;

/// <summary>
/// Declares expected artifact sizes and default encoding hints for a concrete algorithm capability.
/// This is provider-facing metadata only; it does not carry secret material.
/// </summary>
public sealed class CapabilityArtifactProfile
{
    /// <summary>Expected public key size in bytes (0 if not applicable for this algorithm category).</summary>
    public int PublicKeyBytes { get; }

    /// <summary>Expected private key size in bytes (0 if not applicable).</summary>
    public int PrivateKeyBytes { get; }

    /// <summary>Expected KEM ciphertext size in bytes (0 if not a KEM algorithm).</summary>
    public int CiphertextBytes { get; }

    /// <summary>Expected signature size in bytes (0 if not a signature algorithm).</summary>
    public int SignatureBytes { get; }

    /// <summary>Expected shared secret size in bytes (0 if not a KEM/KDF algorithm).</summary>
    public int SharedSecretBytes { get; }

    /// <summary>Expected symmetric key size in bytes (0 if not an AEAD/KDF algorithm).</summary>
    public int SymmetricKeyBytes { get; }

    /// <summary>Expected nonce size in bytes (0 if not an AEAD algorithm).</summary>
    public int NonceBytes { get; }

    /// <summary>Expected authentication tag size in bytes (0 if not an AEAD algorithm).</summary>
    public int TagBytes { get; }

    /// <summary>Default encoding profile for public key import/export.</summary>
    public AlgorithmEncodingProfile PublicKeyEncodingProfile { get; }

    /// <summary>Default encoding profile for private key import/export.</summary>
    public AlgorithmEncodingProfile PrivateKeyEncodingProfile { get; }

    public CapabilityArtifactProfile(
        int publicKeyBytes = 0,
        int privateKeyBytes = 0,
        int ciphertextBytes = 0,
        int signatureBytes = 0,
        int sharedSecretBytes = 0,
        int symmetricKeyBytes = 0,
        int nonceBytes = 0,
        int tagBytes = 0,
        AlgorithmEncodingProfile publicKeyEncodingProfile = AlgorithmEncodingProfile.ProviderNative,
        AlgorithmEncodingProfile privateKeyEncodingProfile = AlgorithmEncodingProfile.ProviderNative)
    {
        if (publicKeyBytes < 0) throw new ArgumentOutOfRangeException(nameof(publicKeyBytes));
        if (privateKeyBytes < 0) throw new ArgumentOutOfRangeException(nameof(privateKeyBytes));
        if (ciphertextBytes < 0) throw new ArgumentOutOfRangeException(nameof(ciphertextBytes));
        if (signatureBytes < 0) throw new ArgumentOutOfRangeException(nameof(signatureBytes));
        if (sharedSecretBytes < 0) throw new ArgumentOutOfRangeException(nameof(sharedSecretBytes));
        if (symmetricKeyBytes < 0) throw new ArgumentOutOfRangeException(nameof(symmetricKeyBytes));
        if (nonceBytes < 0) throw new ArgumentOutOfRangeException(nameof(nonceBytes));
        if (tagBytes < 0) throw new ArgumentOutOfRangeException(nameof(tagBytes));

        PublicKeyBytes = publicKeyBytes;
        PrivateKeyBytes = privateKeyBytes;
        CiphertextBytes = ciphertextBytes;
        SignatureBytes = signatureBytes;
        SharedSecretBytes = sharedSecretBytes;
        SymmetricKeyBytes = symmetricKeyBytes;
        NonceBytes = nonceBytes;
        TagBytes = tagBytes;
        PublicKeyEncodingProfile = publicKeyEncodingProfile;
        PrivateKeyEncodingProfile = privateKeyEncodingProfile;
    }

    public static CapabilityArtifactProfile Empty { get; } = new();
}
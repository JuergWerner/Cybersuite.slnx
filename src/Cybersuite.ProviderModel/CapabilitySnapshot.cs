using System.Buffers;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderModel;

/// <summary>
/// Immutable, thread-safe snapshot of a provider's algorithm capabilities.
/// Created during provider startup after capability exchange and frozen for the session lifetime.
///
/// Includes:
/// <list type="bullet">
///   <item>Sorted (canonical) list of <see cref="AlgorithmDescriptor"/> offerings.</item>
///   <item>Optional <see cref="CapabilityArtifactProfile"/> per algorithm for size/encoding hints.</item>
///   <item>Deterministic SHA-384 hash over canonical JSON for binding, audit, and integrity verification.</item>
/// </list>
///
/// The canonical ordering ensures that the same set of algorithms always produces the same
/// hash, regardless of the order in which the provider reported them.
/// </summary>
public sealed class CapabilitySnapshot
{
    /// <summary>Authenticated identity of the provider that owns these capabilities.</summary>
    public ProviderIdentity Identity { get; }

    /// <summary>Canonically sorted, immutable list of algorithm capabilities offered by this provider.</summary>
    public ImmutableArray<AlgorithmDescriptor> Algorithms { get; }

    /// <summary>
    /// Optional artifact profiles keyed by AlgorithmId.
    /// </summary>
    public ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile> ArtifactProfilesByAlgorithmId { get; }

    /// <summary>
    /// SHA-384 hash of canonical capability JSON bytes (48 bytes).
    /// </summary>
    public ReadOnlyMemory<byte> CapabilityHashSha384 { get; }

    private CapabilitySnapshot(
        ProviderIdentity identity,
        ImmutableArray<AlgorithmDescriptor> algorithms,
        ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile> artifactProfilesByAlgorithmId,
        ReadOnlyMemory<byte> capabilityHashSha384)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        Algorithms = algorithms;
        ArtifactProfilesByAlgorithmId = artifactProfilesByAlgorithmId;

        if (capabilityHashSha384.Length != 48)
            throw new ArgumentException("CapabilityHashSha384 must be 48 bytes (SHA-384).", nameof(capabilityHashSha384));

        CapabilityHashSha384 = capabilityHashSha384;
    }

    public static CapabilitySnapshot Create(
        ProviderIdentity identity,
        ImmutableArray<AlgorithmDescriptor> algorithms,
        ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile>? artifactProfilesByAlgorithmId = null)
    {
        if (identity is null) throw new ArgumentNullException(nameof(identity));
        if (algorithms.IsDefault) throw new ArgumentException("Algorithms must not be default.", nameof(algorithms));

        var arr = new AlgorithmDescriptor[algorithms.Length];
        for (int i = 0; i < algorithms.Length; i++)
        {
            var d = algorithms[i];
            if (d is null)
                throw new ArgumentException("Algorithms must not contain null.", nameof(algorithms));

            if (!d.Provider.Equals(identity.ProviderId))
                throw new ArgumentException("All AlgorithmDescriptor.Provider must match CapabilitySnapshot.Identity.ProviderId.", nameof(algorithms));

            arr[i] = d;
        }

        Array.Sort(arr, AlgorithmDescriptorCanonicalComparer.Instance);
        var sortedAlgorithms = ImmutableArray.Create(arr);

        var profiles = artifactProfilesByAlgorithmId ?? ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile>.Empty;

        foreach (var kv in profiles)
        {
            bool found = false;
            for (int i = 0; i < sortedAlgorithms.Length; i++)
            {
                if (sortedAlgorithms[i].Id.Equals(kv.Key))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
                throw new ArgumentException($"Artifact profile provided for unknown AlgorithmId '{kv.Key.Value}'.", nameof(artifactProfilesByAlgorithmId));
        }

        byte[] canonical = ComputeCanonicalBytes(identity, sortedAlgorithms, profiles);
        byte[] hash = SHA384.HashData(canonical);

        return new CapabilitySnapshot(identity, sortedAlgorithms, profiles, hash);
    }

    public byte[] GetCanonicalBytes()
        => ComputeCanonicalBytes(Identity, Algorithms, ArtifactProfilesByAlgorithmId);

    private static byte[] ComputeCanonicalBytes(
        ProviderIdentity identity,
        ImmutableArray<AlgorithmDescriptor> algorithmsSorted,
        ImmutableDictionary<AlgorithmId, CapabilityArtifactProfile> artifactProfiles)
    {
        var buffer = new ArrayBufferWriter<byte>(4096);

        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false
        }))
        {
            writer.WriteStartObject();

            // Lexicographic key order:
            // algorithms, artifactProfiles, buildHash, providerId, signatureFingerprint, version

            writer.WritePropertyName("algorithms");
            writer.WriteStartArray();

            for (int i = 0; i < algorithmsSorted.Length; i++)
            {
                var d = algorithmsSorted[i];

                int hybridClassicalBits = 0;
                int hybridPqcBits = 0;
                if (d.HybridStrength is not null)
                {
                    hybridClassicalBits = d.HybridStrength.Value.Classical.Bits;
                    hybridPqcBits = d.HybridStrength.Value.PostQuantum.Bits;
                }

                writer.WriteStartObject();

                // Lexicographic order within algorithm object
                writer.WriteString("algorithmId", Normalize(d.Id.Value));
                writer.WriteString("category", d.Category.ToString());
                writer.WriteString("encodingProfile", d.EncodingProfile.ToString());
                writer.WriteNumber("hybridClassicalBits", hybridClassicalBits);
                writer.WriteNumber("hybridPostQuantumBits", hybridPqcBits);
                writer.WriteBoolean("isFipsApproved", d.IsFipsApproved);
                writer.WriteString("operationalMaturity", d.OperationalMaturity.ToString());
                writer.WriteString("parameterSetId", Normalize(d.ParameterSetId?.Value ?? string.Empty));
                writer.WriteString("securityMode", d.SecurityMode.ToString());
                writer.WriteNumber("strengthBits", d.Strength.Bits);

                writer.WriteEndObject();
            }

            writer.WriteEndArray();

            writer.WritePropertyName("artifactProfiles");
            writer.WriteStartObject();

            AlgorithmId[] artifactKeys = artifactProfiles.Keys.ToArray();
            Array.Sort(artifactKeys, static (a, b) => StringComparer.Ordinal.Compare(a.Value, b.Value));

            for (int i = 0; i < artifactKeys.Length; i++)
            {
                AlgorithmId algorithmId = artifactKeys[i];
                CapabilityArtifactProfile profile = artifactProfiles[algorithmId];

                writer.WritePropertyName(Normalize(algorithmId.Value));
                writer.WriteStartObject();

                writer.WriteNumber("ciphertextBytes", profile.CiphertextBytes);
                writer.WriteNumber("nonceBytes", profile.NonceBytes);
                writer.WriteNumber("privateKeyBytes", profile.PrivateKeyBytes);
                writer.WriteString("privateKeyEncodingProfile", profile.PrivateKeyEncodingProfile.ToString());
                writer.WriteNumber("publicKeyBytes", profile.PublicKeyBytes);
                writer.WriteString("publicKeyEncodingProfile", profile.PublicKeyEncodingProfile.ToString());
                writer.WriteNumber("sharedSecretBytes", profile.SharedSecretBytes);
                writer.WriteNumber("signatureBytes", profile.SignatureBytes);
                writer.WriteNumber("symmetricKeyBytes", profile.SymmetricKeyBytes);
                writer.WriteNumber("tagBytes", profile.TagBytes);

                writer.WriteEndObject();
            }

            writer.WriteEndObject();

            writer.WriteString("buildHash", Normalize(identity.BuildHash));
            writer.WriteString("providerId", Normalize(identity.ProviderId.Value));
            writer.WriteString("signatureFingerprint", Normalize(identity.SignatureFingerprint ?? string.Empty));
            writer.WriteString("version", Normalize(identity.Version));

            writer.WriteEndObject();
            writer.Flush();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static string Normalize(string s)
        => (s ?? string.Empty).Normalize(NormalizationForm.FormC);

    private sealed class AlgorithmDescriptorCanonicalComparer : IComparer<AlgorithmDescriptor>
    {
        public static readonly AlgorithmDescriptorCanonicalComparer Instance = new();

        public int Compare(AlgorithmDescriptor? x, AlgorithmDescriptor? y)
        {
            if (ReferenceEquals(x, y)) return 0;
            if (x is null) return -1;
            if (y is null) return 1;

            int c;

            c = ((int)x.Category).CompareTo((int)y.Category);
            if (c != 0) return c;

            c = StringComparer.Ordinal.Compare(x.Id.Value ?? string.Empty, y.Id.Value ?? string.Empty);
            if (c != 0) return c;

            c = StringComparer.Ordinal.Compare(x.Provider.Value ?? string.Empty, y.Provider.Value ?? string.Empty);
            if (c != 0) return c;

            c = x.Strength.Bits.CompareTo(y.Strength.Bits);
            if (c != 0) return c;

            c = ((int)x.SecurityMode).CompareTo((int)y.SecurityMode);
            if (c != 0) return c;

            c = x.IsFipsApproved.CompareTo(y.IsFipsApproved);
            if (c != 0) return c;

            c = ((int)x.OperationalMaturity).CompareTo((int)y.OperationalMaturity);
            if (c != 0) return c;

            c = ((int)x.EncodingProfile).CompareTo((int)y.EncodingProfile);
            if (c != 0) return c;

            c = StringComparer.Ordinal.Compare(
                x.ParameterSetId?.Value ?? string.Empty,
                y.ParameterSetId?.Value ?? string.Empty);
            if (c != 0) return c;

            int xHc = x.HybridStrength?.Classical.Bits ?? 0;
            int yHc = y.HybridStrength?.Classical.Bits ?? 0;
            c = xHc.CompareTo(yHc);
            if (c != 0) return c;

            int xHp = x.HybridStrength?.PostQuantum.Bits ?? 0;
            int yHp = y.HybridStrength?.PostQuantum.Bits ?? 0;
            c = xHp.CompareTo(yHp);
            if (c != 0) return c;

            return 0;
        }
    }
}
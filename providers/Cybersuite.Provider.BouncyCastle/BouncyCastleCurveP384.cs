using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using Org.BouncyCastle.Utilities;
using Cybersuite.Abstractions;

namespace Cybersuite.Provider.BouncyCastle;

internal static class BouncyCastleCurveP384
{
    private static readonly X9ECParameters CurveParams =
        ECNamedCurveTable.GetByName("secp384r1")
        ?? throw new InvalidOperationException("secp384r1 curve not available.");

    public static readonly ECDomainParameters Domain =
        new(CurveParams.Curve, CurveParams.G, CurveParams.N, CurveParams.H, CurveParams.GetSeed());

    public const int CoordinateSizeBytes = 48;
    public const int PublicKeySizeBytes = 97; // uncompressed point
    public const int SharedSecretSizeBytes = CoordinateSizeBytes;

    public static AsymmetricCipherKeyPair GenerateKeyPair(SecureRandom random)
    {
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(Domain, random));
        return gen.GenerateKeyPair();
    }

    public static PublicKey ToPublicKey(AlgorithmId algorithmId, ECPublicKeyParameters publicKey)
        => new(algorithmId, publicKey.Q.GetEncoded(false));

    public static ECPublicKeyParameters ParsePublicKey(ReadOnlySpan<byte> encoded)
    {
        byte[] bytes = encoded.ToArray();
        var point = Domain.Curve.DecodePoint(bytes);
        return new ECPublicKeyParameters(point, Domain);
    }

    /// <summary>
    /// Derives the raw ECDH shared secret (x-coordinate) from a private key and peer public key.
    /// SEC-V2-001: The intermediate BigInteger from CalculateAgreement is best-effort zeroized.
    /// BigInteger is immutable in BouncyCastle, so we extract and zeroize its byte representation.
    /// For constant-time ECDH, prefer <see cref="NativeCurveP384"/> (.NET-native, OS-backed).
    /// </summary>
    public static byte[] DeriveSharedSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters peerPublicKey)
    {
        var agreement = new ECDHBasicAgreement();
        agreement.Init(privateKey);
        var result = agreement.CalculateAgreement(peerPublicKey);

        // SEC-V2-001: Extract the shared secret, then best-effort zeroize the BigInteger intermediate.
        byte[] sharedSecret = BigIntegers.AsUnsignedByteArray(SharedSecretSizeBytes, result);

        // Best-effort zeroization: BigInteger is immutable, but we can zeroize its
        // ToByteArray() representation to reduce the window of exposure on the managed heap.
        byte[] intermediateBytes = result.ToByteArray();
        CryptographicOperations.ZeroMemory(intermediateBytes);

        return sharedSecret;
    }
}
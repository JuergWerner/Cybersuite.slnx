using System;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP request to generate a new KEM key-pair for the specified algorithm
/// (e.g. ML-KEM-768, ECDH-P384-KEM). The provider returns a public key
/// and an opaque private-key handle.
/// </summary>
public sealed class KemGenerateKeyPairRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }

    public KemGenerateKeyPairRequest(OopRequestHeader header, AlgorithmId algorithmId)
    {
        Header = header;
        AlgorithmId = algorithmId;
    }
}

/// <summary>
/// OPP response carrying the freshly generated KEM key-pair.
/// The public key is exported in raw bytes; the private key is
/// held behind an opaque handle managed by the provider.
/// </summary>
public sealed class KemGenerateKeyPairResponse
{
    public OopResponseHeader Header { get; }
    public KemKeyPair KeyPair { get; }

    public KemGenerateKeyPairResponse(OopResponseHeader header, KemKeyPair keyPair)
    {
        Header = header;
        KeyPair = keyPair;
    }
}

/// <summary>
/// OPP request to encapsulate a shared secret using the recipient’s public key.
/// Produces a ciphertext and a shared-secret handle on success.
/// </summary>
public sealed class KemEncapsulateRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }
    public PublicKey RecipientPublicKey { get; }

    public KemEncapsulateRequest(OopRequestHeader header, AlgorithmId algorithmId, in PublicKey recipientPublicKey)
    {
        Header = header;
        AlgorithmId = algorithmId;
        RecipientPublicKey = recipientPublicKey;
    }
}

/// <summary>
/// OPP response carrying the encapsulation result: the ciphertext
/// (to be sent to the recipient) and a shared-secret handle.
/// </summary>
public sealed class KemEncapsulateResponse
{
    public OopResponseHeader Header { get; }
    public KemEncapsulationResult Result { get; }

    public KemEncapsulateResponse(OopResponseHeader header, in KemEncapsulationResult result)
    {
        Header = header;
        Result = result;
    }
}

/// <summary>
/// OPP request to decapsulate a shared secret from a ciphertext
/// using the private key identified by its opaque handle.
/// </summary>
public sealed class KemDecapsulateRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }
    public PrivateKeyHandle PrivateKey { get; }
    public ReadOnlyMemory<byte> Ciphertext { get; }

    public KemDecapsulateRequest(
        OopRequestHeader header,
        AlgorithmId algorithmId,
        PrivateKeyHandle privateKey,
        ReadOnlySpan<byte> ciphertext)
    {
        Header = header;
        AlgorithmId = algorithmId;
        PrivateKey = privateKey;
        Ciphertext = ciphertext.ToArray();
    }
}

/// <summary>
/// OPP response carrying the recovered shared-secret handle after
/// successful decapsulation. The handle references provider-managed memory.
/// </summary>
public sealed class KemDecapsulateResponse
{
    public OopResponseHeader Header { get; }
    public SharedSecretHandle SharedSecret { get; }

    public KemDecapsulateResponse(OopResponseHeader header, SharedSecretHandle sharedSecret)
    {
        Header = header;
        SharedSecret = sharedSecret;
    }
}
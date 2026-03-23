using System;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP request to generate a new digital-signature key-pair for the
/// specified algorithm (e.g. ML-DSA-65, ECDSA-P384).
/// </summary>
public sealed class SignatureGenerateKeyPairRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }

    public SignatureGenerateKeyPairRequest(OopRequestHeader header, AlgorithmId algorithmId)
    {
        Header = header;
        AlgorithmId = algorithmId;
    }
}

/// <summary>
/// OPP response carrying the freshly generated signature key-pair.
/// </summary>
public sealed class SignatureGenerateKeyPairResponse
{
    public OopResponseHeader Header { get; }
    public SignatureKeyPair KeyPair { get; }

    public SignatureGenerateKeyPairResponse(OopResponseHeader header, SignatureKeyPair keyPair)
    {
        Header = header;
        KeyPair = keyPair;
    }
}

/// <summary>
/// OPP request to sign a message with the private key identified
/// by an opaque handle using the specified signature algorithm.
/// </summary>
public sealed class SignatureSignRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }
    public PrivateKeyHandle PrivateKey { get; }
    public ReadOnlyMemory<byte> Message { get; }

    public SignatureSignRequest(
        OopRequestHeader header,
        AlgorithmId algorithmId,
        PrivateKeyHandle privateKey,
        ReadOnlySpan<byte> message)
    {
        Header = header;
        AlgorithmId = algorithmId;
        PrivateKey = privateKey;
        Message = message.ToArray();
    }
}

/// <summary>
/// OPP response carrying the raw signature bytes produced by the provider.
/// </summary>
public sealed class SignatureSignResponse
{
    public OopResponseHeader Header { get; }
    public ReadOnlyMemory<byte> Signature { get; }

    public SignatureSignResponse(OopResponseHeader header, ReadOnlySpan<byte> signature)
    {
        Header = header;
        Signature = signature.ToArray();
    }
}

/// <summary>
/// OPP request to verify a signature against the original message
/// and the public key. Returns a boolean validity result.
/// </summary>
public sealed class SignatureVerifyRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }
    public PublicKey PublicKey { get; }
    public ReadOnlyMemory<byte> Message { get; }
    public ReadOnlyMemory<byte> Signature { get; }

    public SignatureVerifyRequest(
        OopRequestHeader header,
        AlgorithmId algorithmId,
        in PublicKey publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        Header = header;
        AlgorithmId = algorithmId;
        PublicKey = publicKey;
        Message = message.ToArray();
        Signature = signature.ToArray();
    }
}

/// <summary>
/// OPP response indicating whether the signature verification succeeded.
/// </summary>
public sealed class SignatureVerifyResponse
{
    public OopResponseHeader Header { get; }
    public bool IsValid { get; }

    public SignatureVerifyResponse(OopResponseHeader header, bool isValid)
    {
        Header = header;
        IsValid = isValid;
    }
}
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP request to derive a secret key from a shared secret using the
/// specified KDF algorithm (e.g. HKDF-SHA384). Includes salt, info,
/// and desired output length via <see cref="KdfParameters"/>.
/// </summary>
public sealed class KdfDeriveKeyRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }
    public SharedSecretHandle SharedSecretHandle { get; }
    public KdfParameters Parameters { get; }

    public KdfDeriveKeyRequest(
        OopRequestHeader header,
        AlgorithmId algorithmId,
        SharedSecretHandle sharedSecretHandle,
        in KdfParameters parameters)
    {
        Header = header;
        AlgorithmId = algorithmId;
        SharedSecretHandle = sharedSecretHandle;
        Parameters = parameters;
    }
}

/// <summary>
/// OPP response carrying the opaque handle to the newly derived secret key.
/// </summary>
public sealed class KdfDeriveKeyResponse
{
    public OopResponseHeader Header { get; }
    public SecretKeyHandle SecretKeyHandle { get; }

    public KdfDeriveKeyResponse(OopResponseHeader header, SecretKeyHandle secretKeyHandle)
    {
        Header = header;
        SecretKeyHandle = secretKeyHandle;
    }
}
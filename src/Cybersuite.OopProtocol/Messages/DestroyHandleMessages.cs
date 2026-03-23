using System;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// Discriminator indicating which type of opaque handle is being destroyed.
/// </summary>
public enum DestroyHandleKind
{
    PrivateKey = 0,
    SecretKey = 1,
    SharedSecret = 2
}

/// <summary>
/// OPP request to destroy (zeroize and release) a previously issued
/// opaque handle. Callers must destroy handles after use to prevent
/// provider-side memory leaks of sensitive key material.
/// </summary>
public sealed class DestroyHandleRequest
{
    public OopRequestHeader Header { get; }
    public DestroyHandleKind Kind { get; }
    public ProviderId ProviderId { get; }
    public Guid HandleValue { get; }

    public DestroyHandleRequest(
        OopRequestHeader header,
        DestroyHandleKind kind,
        ProviderId providerId,
        Guid handleValue)
    {
        Header = header;
        Kind = kind;
        ProviderId = providerId;
        HandleValue = handleValue;
    }
}

/// <summary>
/// OPP acknowledgement confirming the handle was successfully destroyed.
/// </summary>
public sealed class DestroyHandleResponse
{
    public OopResponseHeader Header { get; }

    public DestroyHandleResponse(OopResponseHeader header)
    {
        Header = header;
    }
}
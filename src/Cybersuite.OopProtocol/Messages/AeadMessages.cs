using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol.Headers;

namespace Cybersuite.OopProtocol.Messages;

/// <summary>
/// OPP request to generate a new symmetric AEAD key (e.g. AES-256-GCM).
/// The provider returns an opaque secret-key handle.
/// </summary>
public sealed class AeadGenerateKeyRequest
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }

    public AeadGenerateKeyRequest(OopRequestHeader header, AlgorithmId algorithmId)
    {
        Header = header;
        AlgorithmId = algorithmId;
    }
}

/// <summary>
/// OPP response carrying the opaque handle to the newly generated AEAD key.
/// </summary>
public sealed class AeadGenerateKeyResponse
{
    public OopResponseHeader Header { get; }
    public SecretKeyHandle KeyHandle { get; }

    public AeadGenerateKeyResponse(OopResponseHeader header, SecretKeyHandle keyHandle)
    {
        Header = header;
        KeyHandle = keyHandle;
    }
}

/// <summary>
/// OPP request to encrypt plaintext with an AEAD algorithm.
/// Includes the key handle, nonce, plaintext, and optional associated data.
/// The nonce must never be reused with the same key (AES-256-GCM requirement).
///
/// F5-FIX: Implements <see cref="IDisposable"/> to zeroize the internal Plaintext copy
/// on dispose, reducing the lifetime of sensitive data on the managed heap.
/// </summary>
public sealed class AeadEncryptRequest : IDisposable
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }
    public SecretKeyHandle KeyHandle { get; }
    public ReadOnlyMemory<byte> Nonce { get; }
    public ReadOnlyMemory<byte> Plaintext { get; }
    public ReadOnlyMemory<byte> AssociatedData { get; }

    public AeadEncryptRequest(
        OopRequestHeader header,
        AlgorithmId algorithmId,
        SecretKeyHandle keyHandle,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        Header = header;
        AlgorithmId = algorithmId;
        KeyHandle = keyHandle;
        Nonce = nonce.ToArray();
        Plaintext = plaintext.ToArray();
        AssociatedData = associatedData.ToArray();
    }

    public void Dispose()
    {
        if (MemoryMarshal.TryGetArray(Plaintext, out ArraySegment<byte> seg) && seg.Array is not null)
            CryptographicOperations.ZeroMemory(seg.Array.AsSpan(seg.Offset, seg.Count));
    }
}

/// <summary>
/// OPP response carrying the ciphertext (including authentication tag)
/// produced by the AEAD encryption.
///
/// F5-FIX: Implements <see cref="IDisposable"/> to zeroize the internal Ciphertext copy.
/// </summary>
public sealed class AeadEncryptResponse : IDisposable
{
    public OopResponseHeader Header { get; }
    public ReadOnlyMemory<byte> Ciphertext { get; }

    public AeadEncryptResponse(OopResponseHeader header, ReadOnlySpan<byte> ciphertext)
    {
        Header = header;
        Ciphertext = ciphertext.ToArray();
    }

    public void Dispose()
    {
        if (MemoryMarshal.TryGetArray(Ciphertext, out ArraySegment<byte> seg) && seg.Array is not null)
            CryptographicOperations.ZeroMemory(seg.Array.AsSpan(seg.Offset, seg.Count));
    }
}

/// <summary>
/// OPP request to decrypt ciphertext with an AEAD algorithm.
/// Verification of the authentication tag is implicit; failure throws.
///
/// F5-FIX: Implements <see cref="IDisposable"/> to zeroize the internal Ciphertext copy.
/// </summary>
public sealed class AeadDecryptRequest : IDisposable
{
    public OopRequestHeader Header { get; }
    public AlgorithmId AlgorithmId { get; }
    public SecretKeyHandle KeyHandle { get; }
    public ReadOnlyMemory<byte> Nonce { get; }
    public ReadOnlyMemory<byte> Ciphertext { get; }
    public ReadOnlyMemory<byte> AssociatedData { get; }

    public AeadDecryptRequest(
        OopRequestHeader header,
        AlgorithmId algorithmId,
        SecretKeyHandle keyHandle,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> associatedData)
    {
        Header = header;
        AlgorithmId = algorithmId;
        KeyHandle = keyHandle;
        Nonce = nonce.ToArray();
        Ciphertext = ciphertext.ToArray();
        AssociatedData = associatedData.ToArray();
    }

    public void Dispose()
    {
        if (MemoryMarshal.TryGetArray(Ciphertext, out ArraySegment<byte> seg) && seg.Array is not null)
            CryptographicOperations.ZeroMemory(seg.Array.AsSpan(seg.Offset, seg.Count));
    }
}

/// <summary>
/// OPP response carrying the recovered plaintext after successful
/// AEAD decryption and authentication-tag verification.
///
/// F5-FIX: Implements <see cref="IDisposable"/> to zeroize the internal Plaintext copy.
/// </summary>
public sealed class AeadDecryptResponse : IDisposable
{
    public OopResponseHeader Header { get; }
    public bool IsValid { get; }
    public ReadOnlyMemory<byte> Plaintext { get; }

    public AeadDecryptResponse(OopResponseHeader header, bool isValid, ReadOnlySpan<byte> plaintext)
    {
        Header = header;
        IsValid = isValid;
        Plaintext = plaintext.ToArray();
    }

    public void Dispose()
    {
        if (MemoryMarshal.TryGetArray(Plaintext, out ArraySegment<byte> seg) && seg.Array is not null)
            CryptographicOperations.ZeroMemory(seg.Array.AsSpan(seg.Offset, seg.Count));
    }
}
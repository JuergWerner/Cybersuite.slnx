using System;
using System.Security.Cryptography;

namespace Cybersuite.Abstractions;

/// <summary>
/// Disposable wrapper around secret byte material that guarantees zeroization on disposal.
/// Prevents uncontrolled secret byte[] copies from leaking into the managed heap.
/// 
/// Usage:
/// <code>
/// using var secret = exportService.ExportPrivateKeySecure(handle, options);
/// DoWork(secret.Span);
/// // Automatically zeroed when disposed
/// </code>
/// 
/// This type is a value type (struct) to avoid GC overhead and to keep the secret
/// material in a single, predictable heap location.
/// </summary>
public readonly struct SecretBytes : IDisposable
{
    private readonly byte[] _data;

    public SecretBytes(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    /// <summary>Read-only span over the secret material. Valid only while not disposed.</summary>
    public ReadOnlySpan<byte> Span => _data;

    /// <summary>Length of the secret material in bytes.</summary>
    public int Length => _data?.Length ?? 0;

    /// <summary>Whether this instance wraps valid data.</summary>
    public bool IsEmpty => _data is null || _data.Length == 0;

    /// <summary>
    /// Zeroizes the underlying byte array, preventing residual secret material in the heap.
    /// Safe to call multiple times.
    /// </summary>
    public void Dispose()
    {
        if (_data is not null)
        {
            CryptographicOperations.ZeroMemory(_data);
        }
    }
}

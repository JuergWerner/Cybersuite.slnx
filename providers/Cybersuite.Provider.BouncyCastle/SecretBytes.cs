using System;
using System.Security.Cryptography;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Disposable wrapper around secret byte material that guarantees zeroization on disposal.
/// Prevents uncontrolled secret byte[] copies from leaking into the managed heap.
/// 
/// Usage:
/// <code>
/// using var secret = store.BorrowSecretKey(handle);
/// DoWork(secret.Span);
/// // Automatically zeroed when disposed
/// </code>
/// 
/// SEC-H-003: Replaces raw byte[] returns from GetSecretKeyCopy/GetSharedSecretCopy.
/// </summary>
internal readonly struct SecretBytes : IDisposable
{
    private readonly byte[] _data;

    internal SecretBytes(byte[] data)
    {
        _data = data ?? throw new ArgumentNullException(nameof(data));
    }

    /// <summary>
    /// Read-only span over the secret material. Valid only while not disposed.
    /// </summary>
    public ReadOnlySpan<byte> Span => _data;

    /// <summary>
    /// Length of the secret material in bytes.
    /// </summary>
    public int Length => _data.Length;

    /// <summary>
    /// Zeroizes the underlying byte array, preventing residual secret material in the heap.
    /// </summary>
    public void Dispose()
    {
        if (_data is not null)
        {
            CryptographicOperations.ZeroMemory(_data);
        }
    }
}

using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading;

namespace Cybersuite.Abstractions;

/// <summary>
/// Disposable lease over a byte buffer rented from <see cref="ArrayPool{T}.Shared"/>.
/// On <see cref="Dispose"/>, the used portion is zeroized via
/// <see cref="CryptographicOperations.ZeroMemory"/> and the buffer is returned to the pool.
///
/// This type reduces GC-visible heap copies of sensitive data (secret keys, shared secrets,
/// plaintext) by reusing pooled buffers and guaranteeing deterministic zeroization.
///
/// Usage:
/// <code>
/// using var lease = SensitiveBufferLease.CopyFrom(sensitiveSpan);
/// DoWork(lease.Span);
/// // Automatically zeroized and returned to pool
/// </code>
///
/// Thread-safety: A single instance must not be shared across threads without external
/// synchronization. <see cref="Dispose"/> is safe to call exactly once; concurrent or
/// repeated calls are guarded via <see cref="Interlocked.Exchange{T}"/>.
///
/// F5-FIX: Replaces bare <c>ToArray()</c> copies of sensitive byte material throughout
/// the provider stack with pooled, zeroizable buffers.
/// </summary>
public sealed class SensitiveBufferLease : IDisposable
{
    private byte[]? _rented;
    private readonly int _length;

    private SensitiveBufferLease(byte[] rented, int length)
    {
        _rented = rented;
        _length = length;
    }

    /// <summary>
    /// Rents a buffer of at least <paramref name="length"/> bytes from the shared pool.
    /// The caller-visible portion (<see cref="Span"/>) is exactly <paramref name="length"/> bytes.
    /// The buffer content is uninitialized; the caller must write to it before reading.
    /// </summary>
    public static SensitiveBufferLease Rent(int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);
        byte[] buf = ArrayPool<byte>.Shared.Rent(length);
        return new SensitiveBufferLease(buf, length);
    }

    /// <summary>
    /// Rents a buffer and copies <paramref name="source"/> into it.
    /// This is the primary replacement for <c>span.ToArray()</c> on sensitive data.
    /// </summary>
    public static SensitiveBufferLease CopyFrom(ReadOnlySpan<byte> source)
    {
        var lease = Rent(source.Length);
        source.CopyTo(lease.Span);
        return lease;
    }

    /// <summary>
    /// Writable span over the used portion of the rented buffer.
    /// Throws <see cref="ObjectDisposedException"/> if already disposed.
    /// </summary>
    public Span<byte> Span
    {
        get
        {
            byte[]? buf = _rented;
            ObjectDisposedException.ThrowIf(buf is null, this);
            return buf.AsSpan(0, _length);
        }
    }

    /// <summary>
    /// Read-only span over the used portion of the rented buffer.
    /// </summary>
    public ReadOnlySpan<byte> ReadOnlySpan => Span;

    /// <summary>
    /// The exact number of usable bytes (not the rented array length).
    /// </summary>
    public int Length => _length;

    /// <summary>
    /// Returns the underlying rented array for APIs that require <c>byte[]</c>
    /// (e.g., BouncyCastle <c>KeyParameter</c>). The caller must use
    /// <see cref="Length"/> as the effective length — the rented array may be larger.
    /// </summary>
    public byte[] DangerousGetArray()
    {
        byte[]? buf = _rented;
        ObjectDisposedException.ThrowIf(buf is null, this);
        return buf;
    }

    /// <summary>
    /// Zeroizes the used portion and returns the buffer to the shared pool.
    /// Safe to call once; subsequent calls are no-ops.
    /// </summary>
    public void Dispose()
    {
        byte[]? buf = Interlocked.Exchange(ref _rented, null);
        if (buf is not null)
        {
            CryptographicOperations.ZeroMemory(buf.AsSpan(0, _length));
            ArrayPool<byte>.Shared.Return(buf);
        }
    }
}

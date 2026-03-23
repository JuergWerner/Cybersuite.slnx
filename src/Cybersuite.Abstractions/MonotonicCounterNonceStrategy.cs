using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;

namespace Cybersuite.Abstractions;

/// <summary>
/// Monotonic counter-based nonce strategy for AEAD.
/// 
/// Generates nonces as big-endian counter values, optionally XOR'd with a random prefix
/// for domain separation across sessions. The counter is incremented atomically,
/// making this strategy thread-safe.
/// 
/// Nonce format (for 12-byte / 96-bit nonces):
/// <code>
/// [4-byte random session prefix] [8-byte big-endian counter]
/// </code>
/// 
/// This supports 2^63 encryptions per session before exhaustion (throws).
/// For AES-256-GCM with 96-bit nonces, this is the NIST-recommended approach.
/// </summary>
public sealed class MonotonicCounterNonceStrategy : IAeadNonceStrategy
{
    private readonly byte[] _prefix;
    private readonly int _nonceSize;
    private long _counter;

    /// <summary>
    /// Creates a new counter-based nonce strategy.
    /// </summary>
    /// <param name="nonceSize">Nonce size in bytes (typically 12 for AES-GCM).</param>
    /// <exception cref="ArgumentOutOfRangeException">Nonce size must be at least 8 bytes (for the counter).</exception>
    public MonotonicCounterNonceStrategy(int nonceSize = 12)
    {
        if (nonceSize < 8)
            throw new ArgumentOutOfRangeException(nameof(nonceSize), "Nonce must be at least 8 bytes for the counter.");

        _nonceSize = nonceSize;

        // Random prefix fills the leading bytes (nonceSize - 8) for session uniqueness
        int prefixLen = nonceSize - 8;
        _prefix = new byte[prefixLen];
        if (prefixLen > 0)
            RandomNumberGenerator.Fill(_prefix);
    }

    public int NonceSize => _nonceSize;

    public long GeneratedCount => Interlocked.Read(ref _counter);

    public void NextNonce(Span<byte> destination)
    {
        if (destination.Length < _nonceSize)
            throw new ArgumentException($"Destination must be at least {_nonceSize} bytes.", nameof(destination));

        long value = Interlocked.Increment(ref _counter);

        // Overflow guard: signed long wraps to negative after long.MaxValue
        if (value <= 0)
            throw new InvalidOperationException(
                "Nonce counter exhausted. Re-key the AEAD session to continue encrypting.");

        // Write prefix (session-random) + counter (big-endian)
        _prefix.AsSpan().CopyTo(destination);
        BinaryPrimitives.WriteInt64BigEndian(destination[_prefix.Length..], value);

        // Zero any trailing bytes if destination is larger
        if (destination.Length > _nonceSize)
            destination[_nonceSize..].Clear();
    }

    public void Dispose()
    {
        // Zeroize the prefix to prevent session correlation
        CryptographicOperations.ZeroMemory(_prefix);
    }
}

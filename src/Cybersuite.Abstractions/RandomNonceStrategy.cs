using System;
using System.Security.Cryptography;
using System.Threading;

namespace Cybersuite.Abstractions;

/// <summary>
/// Random nonce strategy for AEAD with birthday-bound collision tracking.
/// 
/// Generates nonces via <see cref="RandomNumberGenerator"/> (CSPRNG) and tracks
/// the number of generated nonces to enforce a configurable collision probability
/// threshold based on the birthday bound.
/// 
/// For AES-256-GCM with 96-bit nonces:
/// - After 2^32 (~4.3 billion) encryptions, collision probability ≈ 2^-32 (acceptable for most uses)
/// - After 2^48 encryptions, collision probability ≈ 2^0 (unacceptable)
/// 
/// Default threshold: 2^32 (conservative). Configurable via constructor.
/// </summary>
public sealed class RandomNonceStrategy : IAeadNonceStrategy
{
    /// <summary>
    /// Default collision threshold: 2^32 nonces for 96-bit nonces.
    /// At this count, P(collision) ≈ 2^-32 ≈ 1 in 4 billion.
    /// </summary>
    public const long DefaultCollisionThreshold = 1L << 32;

    private readonly int _nonceSize;
    private readonly long _collisionThreshold;
    private long _counter;

    /// <summary>
    /// Creates a new random nonce strategy with collision tracking.
    /// </summary>
    /// <param name="nonceSize">Nonce size in bytes (typically 12 for AES-GCM).</param>
    /// <param name="collisionThreshold">
    /// Maximum number of nonces before the strategy refuses to generate more.
    /// Default: 2^32 (conservative for 96-bit nonces).
    /// </param>
    public RandomNonceStrategy(int nonceSize = 12, long collisionThreshold = DefaultCollisionThreshold)
    {
        if (nonceSize < 8)
            throw new ArgumentOutOfRangeException(nameof(nonceSize), "Nonce must be at least 8 bytes.");
        if (collisionThreshold <= 0)
            throw new ArgumentOutOfRangeException(nameof(collisionThreshold), "Threshold must be positive.");

        _nonceSize = nonceSize;
        _collisionThreshold = collisionThreshold;
    }

    public int NonceSize => _nonceSize;

    public long GeneratedCount => Interlocked.Read(ref _counter);

    /// <summary>
    /// The configured collision threshold. When <see cref="GeneratedCount"/> reaches this value,
    /// <see cref="NextNonce"/> will throw, requiring the caller to re-key.
    /// </summary>
    public long CollisionThreshold => _collisionThreshold;

    public void NextNonce(Span<byte> destination)
    {
        if (destination.Length < _nonceSize)
            throw new ArgumentException($"Destination must be at least {_nonceSize} bytes.", nameof(destination));

        long count = Interlocked.Increment(ref _counter);

        if (count > _collisionThreshold)
            throw new InvalidOperationException(
                $"Random nonce collision threshold exceeded ({_collisionThreshold}). " +
                "Re-key the AEAD session to continue encrypting safely.");

        RandomNumberGenerator.Fill(destination[.._nonceSize]);

        // Zero any trailing bytes if destination is larger
        if (destination.Length > _nonceSize)
            destination[_nonceSize..].Clear();
    }

    public void Dispose()
    {
        // No secret state to zeroize; counter is not sensitive.
    }
}

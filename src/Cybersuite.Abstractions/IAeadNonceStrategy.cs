using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Structural nonce-reuse protection for AEAD operations.
/// 
/// Instead of relying on callers to manage nonce uniqueness (SEC-M-004),
/// this interface provides a state-machine that guarantees nonce uniqueness
/// per key session. Implementations must be thread-safe.
/// 
/// Usage:
/// <code>
/// using var strategy = new MonotonicCounterNonceStrategy(nonceSize: 12);
/// Span&lt;byte&gt; nonce = stackalloc byte[12];
/// strategy.NextNonce(nonce);
/// aeadService.Encrypt(key, nonce, plaintext, aad, ciphertextOut);
/// </code>
/// </summary>
public interface IAeadNonceStrategy : IDisposable
{
    /// <summary>Nonce size in bytes that this strategy produces.</summary>
    int NonceSize { get; }

    /// <summary>
    /// Generates the next unique nonce and writes it to <paramref name="destination"/>.
    /// Throws <see cref="InvalidOperationException"/> if the nonce space is exhausted
    /// (e.g., counter overflow) or a collision risk threshold is exceeded.
    /// </summary>
    /// <param name="destination">Buffer of at least <see cref="NonceSize"/> bytes.</param>
    /// <exception cref="InvalidOperationException">Nonce space exhausted or collision threshold exceeded.</exception>
    void NextNonce(Span<byte> destination);

    /// <summary>
    /// Number of nonces generated so far. Used for monitoring and collision tracking.
    /// </summary>
    long GeneratedCount { get; }
}

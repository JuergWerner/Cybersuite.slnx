using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Authenticated Encryption with Associated Data (AEAD) service contract.
/// Supports algorithms like AES-256-GCM and ChaCha20-Poly1305.
/// Part of the provider service model defined in [PM-000].
/// 
/// Convention: ciphertext includes the authentication tag appended at the end.
/// - <see cref="GetCiphertextSize"/>: plaintext size + <see cref="TagSize"/>.
/// - <see cref="GetPlaintextSize"/>: ciphertext size - <see cref="TagSize"/>.
/// 
/// Security requirements (provider responsibility per [SEC-SC-000]):
/// - <see cref="Decrypt"/> must perform tag validation in constant time to prevent
///   timing side-channel attacks.
/// - Key material is referenced via opaque <see cref="SecretKeyHandle"/> and never
///   leaves the provider boundary as raw bytes.
/// 
/// Thread-safety: implementations must be safe for concurrent use (per <see cref="ICryptoService"/>).
/// </summary>
public interface IAeadService : ICryptoService
{
    /// <summary>Symmetric key size in bytes.</summary>
    int KeySize { get; }

    /// <summary>Nonce (IV) size in bytes.</summary>
    int NonceSize { get; }

    /// <summary>Authentication tag size in bytes.</summary>
    int TagSize { get; }

    /// <summary>Generates a fresh symmetric key. Returns an opaque handle to the key material.</summary>
    SecretKeyHandle GenerateKey();

    /// <summary>Returns the ciphertext size (including tag) for a given plaintext size.</summary>
    int GetCiphertextSize(int plaintextSize);

    /// <summary>Returns the plaintext size for a given ciphertext size (excluding tag).</summary>
    int GetPlaintextSize(int ciphertextSize);

    /// <summary>
    /// Encrypts plaintext with associated data. The ciphertext (including appended tag)
    /// is written to <paramref name="ciphertextOut"/>.
    /// <para>
    /// <b>SEC-M-004 — CRITICAL NONCE SAFETY WARNING:</b> The caller is responsible for ensuring
    /// nonce uniqueness per key. Reusing a nonce with the same key under AES-GCM is
    /// catastrophically insecure (enables key recovery and forgery attacks).
    /// Recommended: use a monotonic counter or generate random nonces of sufficient size
    /// (≥96 bits) with collision probability tracking. Never reuse a (key, nonce) pair.
    /// </para>
    /// </summary>
    void Encrypt(
        SecretKeyHandle key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> ciphertextOut);

    /// <summary>
    /// Decrypts ciphertext with associated data. Returns true if tag verification succeeds
    /// and the plaintext is written to <paramref name="plaintextOut"/>; false if authentication fails.
    /// Tag validation must be performed in constant time.
    /// </summary>
    bool Decrypt(
        SecretKeyHandle key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> associatedData,
        Span<byte> plaintextOut);
}
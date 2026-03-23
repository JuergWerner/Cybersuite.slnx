using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Parameters for a key derivation operation (e.g., HKDF).
/// Passed to <see cref="IKdfService.DeriveKey"/>.
/// 
/// - <see cref="Salt"/>: Optional salt input (can be empty for HKDF with zero-length salt).
/// - <see cref="Info"/>: Context/application-specific info (e.g., protocol label, transcript binding).
/// - <see cref="OutputKeyBits"/>: Desired output key size in bits.
/// 
/// Security note: Salt and Info are non-secret context parameters. The actual secret input
/// (<see cref="SharedSecretHandle"/>) is passed separately to the KDF service as an opaque handle.
/// </summary>
public readonly record struct KdfParameters(
    ReadOnlyMemory<byte> Salt,
    ReadOnlyMemory<byte> Info,
    int OutputKeyBits
);
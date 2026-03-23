using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Result of a KEM encapsulation operation: ciphertext + shared secret handle.
/// Returned by <see cref="IKemService.Encapsulate"/>.
/// 
/// The <see cref="Ciphertext"/> is sent to the decapsulator (key holder).
/// The <see cref="SharedSecret"/> handle references the derived shared secret inside
/// the provider boundary — the Core never sees the raw shared secret bytes.
/// </summary>
public readonly record struct KemEncapsulationResult(ReadOnlyMemory<byte> Ciphertext, SharedSecretHandle SharedSecret);
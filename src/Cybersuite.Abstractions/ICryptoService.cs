namespace Cybersuite.Abstractions;

/// <summary>
/// Base interface for all cryptographic service abstractions (KEM, Signature, AEAD, KDF).
/// Every service is bound to a specific provider and algorithm, enabling the Runtime to
/// route operations through the correct provider session [ARC-100].
/// Implements <see cref="IDisposable"/> to allow deterministic release of provider-side resources.
/// </summary>
public interface ICryptoService : IDisposable
{
    ProviderId ProviderId { get; }
    AlgorithmId AlgorithmId { get; }
    AlgorithmCategory Category { get; }
}
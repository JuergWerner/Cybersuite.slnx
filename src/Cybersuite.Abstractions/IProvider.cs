using System.Collections.Immutable;

namespace Cybersuite.Abstractions;

/// <summary>
/// Logical provider abstraction. Defined in [PM-000] (ProviderModel).
/// 
/// In the preferred out-of-process model (see [OOP-000]), this interface is NOT implemented
/// by the provider process itself. Instead, the ProviderHost creates an adapter that maps
/// these calls to OOP protocol messages (handshake, capability exchange, session open/close).
/// 
/// In the in-process model (for testing or simple deployments), a provider can implement
/// this interface directly.
/// 
/// Lifecycle:
/// 1. <see cref="Initialize"/> — idempotent startup (ProviderHost maps to process launch + handshake).
/// 2. <see cref="GetCapabilities"/> — returns the immutable capability snapshot.
/// 3. <see cref="OpenSession"/> — creates a policy-bound session for crypto operations.
/// 4. <see cref="Shutdown"/> — graceful teardown (ProviderHost maps to shutdown message + zeroization + process kill).
/// 
/// Thread-safety: implementations must be safe for concurrent use. Sessions opened via
/// <see cref="OpenSession"/> are independently thread-safe.
/// </summary>
public interface IProvider
{
    /// <summary>Unique provider identifier.</summary>
    ProviderId Id { get; }

    /// <summary>
    /// Provider initialization (idempotent). In the OOP model, the ProviderHost maps this
    /// to process start, handshake, and capability exchange.
    /// </summary>
    void Initialize();

    /// <summary>
    /// Immutable snapshot of algorithms currently offered by this provider.
    /// The array content must not change after initialization.
    /// </summary>
    ImmutableArray<AlgorithmDescriptor> GetCapabilities();

    /// <summary>
    /// Opens a session bound to a policy hash and tenant scope. The session provides access
    /// to algorithm-specific services (KEM, Signature, AEAD, KDF).
    /// Sessions must be thread-safe by contract.
    /// </summary>
    IProviderSession OpenSession(in ProviderSessionOptions options);

    /// <summary>
    /// Provider shutdown (graceful). In the OOP model, the ProviderHost maps this to a
    /// shutdown request, zeroization of all key material, and process termination.
    /// </summary>
    void Shutdown();
}
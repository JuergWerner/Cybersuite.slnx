using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Opaque handle to a private key residing in the provider boundary.
/// Part of the handle-based secret management model defined in [OOP-040] and [ARC-010].
///// 
/// The Core runtime never sees raw private key bytes — only this opaque handle.
/// The actual key material lives inside the provider process (or HSM) and is
/// referenced exclusively by this handle. This design ensures:
/// - No secret leakage across trust boundaries.
/// - No accidental logging of key material (handles are safe to reference but should
///   still not appear in production logs per [SEC-SC-000]).
/// - Clean separation between Core (unprivileged) and Provider (secrets boundary).
/// 
/// Lifecycle: the handle is valid for the lifetime of the <see cref="IProviderSession"/>
/// that created it. Call <see cref="IProviderSession.Destroy(PrivateKeyHandle)"/> to
/// request zeroization of the underlying key material.
/// </summary>
public readonly record struct PrivateKeyHandle(ProviderId ProviderId, Guid Value);
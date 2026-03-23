using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Opaque handle to a symmetric key residing in the provider boundary.
/// Part of the handle-based secret management model defined in [OOP-040] and [ARC-010].
/// 
/// Symmetric keys (e.g., AEAD keys, derived keys) never leave the provider process as raw bytes.
/// The Core runtime references them via this handle when calling <see cref="IAeadService"/>
/// encrypt/decrypt operations. This prevents secret leakage across trust boundaries.
/// 
/// Lifecycle: the handle is valid for the lifetime of the <see cref="IProviderSession"/>
/// that created it. Call <see cref="IProviderSession.Destroy(SecretKeyHandle)"/> to
/// request zeroization of the underlying key material.
/// </summary>
public readonly record struct SecretKeyHandle(ProviderId ProviderId, Guid Value);
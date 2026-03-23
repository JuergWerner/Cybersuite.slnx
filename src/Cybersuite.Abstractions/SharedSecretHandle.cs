using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Opaque handle to a shared secret (e.g., KEM output) residing in the provider boundary.
/// Part of the handle-based secret management model defined in [OOP-040] and [ARC-010].
/// 
/// A shared secret is the output of a KEM decapsulation or key exchange operation. It is
/// consumed by a <see cref="IKdfService"/> to derive symmetric keys. The raw shared secret
/// bytes never cross the provider trust boundary — only this handle is visible to the Core.
/// 
/// Lifecycle: the handle is valid for the lifetime of the <see cref="IProviderSession"/>
/// that created it. Call <see cref="IProviderSession.Destroy(SharedSecretHandle)"/> to
/// request zeroization of the underlying shared secret material.
/// </summary>
public readonly record struct SharedSecretHandle(ProviderId ProviderId, Guid Value);
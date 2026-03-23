using System;

namespace Cybersuite.Abstractions;

/// <summary>
/// Non-secret contextual constraints passed to the selection engine at selection time.
/// Defined in [ARC-030] (Snapshot-Philosophie) and [SEL-000] (Algorithm Selection).
/// 
/// <b>Security invariant:</b> This struct must never contain secret material (keys, tokens, etc.).
/// It carries only non-sensitive metadata needed to parameterize selection:
/// - <see cref="TenantId"/>: Optional multi-tenant scope. When present, the selection/policy
///   pipeline can restrict algorithms to those approved for a specific tenant.
/// - <see cref="Profile"/>: Execution profile that governs strictness of security gates.
/// - <see cref="ForceFips"/>: Optional FIPS override. When null, the policy's own
///   <see cref="IPolicy.FipsRequired"/> flag is used. When true/false, this value takes
///   precedence (e.g., set by a Compliance decorator layer per [FIPS-000]).
/// 
/// Thread-safety: immutable readonly record struct — safe to pass by value across threads.
/// </summary>
public readonly record struct SelectionContext(
    string? TenantId,
    ExecutionProfile Profile,
    bool? ForceFips // null => use policy.FipsRequired; true/false => override
);
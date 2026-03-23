using System;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace Cybersuite.Runtime;

/// <summary>
/// Runtime audit event. Must not include secrets, handles, plaintext policy bytes, or raw key material.
/// </summary>
public sealed record RuntimeAuditEvent
{
    public required string EventType { get; init; }
    public required DateTimeOffset UtcTimestamp { get; init; }

    public required ImmutableArray<byte> PolicyHashSha384 { get; init; }
    public string? TenantId { get; init; }

    public int SelectedCategoryCount { get; init; }
    public bool EffectiveFipsRequired { get; init; }
    public string? RequiredBoundaryClass { get; init; }
    public ImmutableArray<string> ProviderIds { get; init; } = ImmutableArray<string>.Empty;

    public static RuntimeAuditEvent CreateInitialized(RuntimeScope scope)
    {
        var set = new SortedSet<string>(StringComparer.Ordinal);

        foreach (var kv in scope.SelectionPlan)
        {
            set.Add(kv.Value.ProviderId.Value);
        }

        return new RuntimeAuditEvent
        {
            EventType = "runtime.initialized",
            UtcTimestamp = DateTimeOffset.UtcNow,
            PolicyHashSha384 = scope.SessionBinding.PolicyHashSha384,
            TenantId = scope.Context.TenantId,
            SelectedCategoryCount = scope.SelectionPlan.Count,
            EffectiveFipsRequired = scope.EffectiveCompliance?.EffectiveFipsRequired ?? scope.SessionBinding.FipsRequired,
            RequiredBoundaryClass = scope.EffectiveCompliance?.RequiredBoundaryClass.ToString(),
            ProviderIds = ImmutableArray.CreateRange(set)
        };
    }

    public static RuntimeAuditEvent CreateShutdown(RuntimeScope? scope)
    {
        ImmutableArray<byte> policyHash = ImmutableArray<byte>.Empty;
        string? tenantId = null;
        bool effectiveFipsRequired = false;
        string? requiredBoundaryClass = null;

        if (scope is not null)
        {
            policyHash = scope.SessionBinding.PolicyHashSha384;
            tenantId = scope.Context.TenantId;
            effectiveFipsRequired = scope.EffectiveCompliance?.EffectiveFipsRequired ?? scope.SessionBinding.FipsRequired;
            requiredBoundaryClass = scope.EffectiveCompliance?.RequiredBoundaryClass.ToString();
        }

        return new RuntimeAuditEvent
        {
            EventType = "runtime.shutdown",
            UtcTimestamp = DateTimeOffset.UtcNow,
            PolicyHashSha384 = policyHash,
            TenantId = tenantId,
            SelectedCategoryCount = 0,
            EffectiveFipsRequired = effectiveFipsRequired,
            RequiredBoundaryClass = requiredBoundaryClass,
            ProviderIds = ImmutableArray<string>.Empty
        };
    }
}
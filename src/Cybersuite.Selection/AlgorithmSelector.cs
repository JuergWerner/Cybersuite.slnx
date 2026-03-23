using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Cybersuite.Abstractions;

namespace Cybersuite.Selection;

/// <summary>
/// Deterministic, fail-closed algorithm selection.
/// Thread-safe by design: no shared mutable state; purely derived from inputs.
/// </summary>
public sealed class AlgorithmSelector : ISelectionEngine
{
    public ImmutableDictionary<AlgorithmCategory, AlgorithmDescriptor> Select(
        IPolicy policy,
        ImmutableArray<AlgorithmDescriptor> capabilities,
        in SelectionContext context)
    {
        if (policy is null) throw new ArgumentNullException(nameof(policy));
        if (capabilities.IsDefault) throw new ArgumentException("Capabilities must not be default.", nameof(capabilities));

        bool fipsWanted = context.ForceFips ?? policy.FipsRequired;

        // Build provider allowlist set once (local; no shared state)
        HashSet<ProviderId>? providerAllowSet = null;
        if (!policy.ProviderAllowlist.IsDefaultOrEmpty && policy.ProviderAllowlist.Length > 0)
        {
            providerAllowSet = new HashSet<ProviderId>();
            for (int i = 0; i < policy.ProviderAllowlist.Length; i++)
                providerAllowSet.Add(policy.ProviderAllowlist[i]);
        }

        var result = ImmutableDictionary.CreateBuilder<AlgorithmCategory, AlgorithmDescriptor>();

        foreach (var kv in policy.MinimumStrengthByCategory)
        {
            AlgorithmCategory category = kv.Key;
            SecurityStrength minStrength = kv.Value;

            AlgorithmDescriptor? best = null;

            for (int i = 0; i < capabilities.Length; i++)
            {
                var d = capabilities[i];
                if (d is null)
                    continue;

                if (d.Category != category)
                    continue;

                if (d.Strength < minStrength)
                    continue;

                if (providerAllowSet is not null && !providerAllowSet.Contains(d.Provider))
                    continue;

                // Pinning precedence: algorithm-level pin > category-level pin
                if (policy.PinnedProviderByAlgorithm.TryGetValue(d.Id, out var pinnedAlgProvider))
                {
                    if (!d.Provider.Equals(pinnedAlgProvider))
                        continue;
                }
                else if (policy.PinnedProviderByCategory.TryGetValue(category, out var pinnedCatProvider))
                {
                    if (!d.Provider.Equals(pinnedCatProvider))
                        continue;
                }

                // FIPS gating (used by Compliance layer by setting context.ForceFips)
                if (fipsWanted && !d.IsFipsApproved)
                    continue;

                // SecurityMode enforcement for asymmetric categories only
                if (IsAsymmetricCategory(category))
                {
                    if (!IsAllowedMode(policy.SecurityMode, d.SecurityMode))
                        continue;
                }

                if (best is null || IsBetterCandidate(d, best))
                    best = d;
            }

            if (best is null)
            {
                throw new SelectionFailedException(
                    category,
                    $"No candidate satisfies policy constraints for category '{category}'.");
            }

            result[category] = best;
        }

        return result.ToImmutable();
    }

    private static bool IsAsymmetricCategory(AlgorithmCategory category)
    {
        return category == AlgorithmCategory.KeyEncapsulation
            || category == AlgorithmCategory.KeyExchange
            || category == AlgorithmCategory.Signature;
    }

    private static bool IsAllowedMode(PolicySecurityMode policyMode, AlgorithmSecurityMode algorithmMode)
    {
        return policyMode switch
        {
            PolicySecurityMode.Classical => algorithmMode == AlgorithmSecurityMode.Classical,
            PolicySecurityMode.Pqc => algorithmMode == AlgorithmSecurityMode.Pqc,
            PolicySecurityMode.Hybrid => algorithmMode == AlgorithmSecurityMode.Hybrid,
            _ => false
        };
    }

    /// <summary>
    /// Max strength wins. Tie-break: ProviderId lexicographic (Ordinal ascending), then AlgorithmId lexicographic.
    /// Deterministic regardless of capability input ordering.
    /// </summary>
    private static bool IsBetterCandidate(AlgorithmDescriptor candidate, AlgorithmDescriptor currentBest)
    {
        if (candidate.Strength > currentBest.Strength)
            return true;

        if (candidate.Strength < currentBest.Strength)
            return false;

        string cProv = candidate.Provider.Value ?? string.Empty;
        string bProv = currentBest.Provider.Value ?? string.Empty;

        int p = StringComparer.Ordinal.Compare(cProv, bProv);
        if (p < 0) return true;
        if (p > 0) return false;

        string cAlg = candidate.Id.Value ?? string.Empty;
        string bAlg = currentBest.Id.Value ?? string.Empty;

        return StringComparer.Ordinal.Compare(cAlg, bAlg) < 0;
    }
}
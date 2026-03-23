using System.Collections.Immutable;
using Cybersuite.Abstractions;
using Cybersuite.ProviderHost;

namespace Cybersuite.Runtime;

/// <summary>
/// Immutable runtime scope: one policy-bound, profile-bound, provider-host-backed selection context.
/// </summary>
public sealed class RuntimeScope
{
    public IPolicy Policy { get; }
    public SelectionContext Context { get; }
    public ProviderSessionBinding SessionBinding { get; }
    public ProviderRegistrySnapshot RegistrySnapshot { get; }

    public EffectiveComplianceContext? EffectiveCompliance => SessionBinding.EffectiveCompliance;

    public ImmutableDictionary<AlgorithmCategory, RuntimeSelectionPlanEntry> SelectionPlan { get; }

    public RuntimeScope(
        IPolicy policy,
        SelectionContext context,
        ProviderSessionBinding sessionBinding,
        ProviderRegistrySnapshot registrySnapshot,
        ImmutableDictionary<AlgorithmCategory, RuntimeSelectionPlanEntry> selectionPlan)
    {
        Policy = policy;
        Context = context;
        SessionBinding = sessionBinding;
        RegistrySnapshot = registrySnapshot;
        SelectionPlan = selectionPlan;
    }
}
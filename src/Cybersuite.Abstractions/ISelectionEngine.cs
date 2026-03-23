using System.Collections.Immutable;

namespace Cybersuite.Abstractions;

/// <summary>
/// Deterministic, fail-closed selection engine contract. Defined in [SEL-000].
/// 
/// Given an immutable policy snapshot and a set of provider capabilities, the engine
/// resolves exactly one winning <see cref="AlgorithmDescriptor"/> per category that
/// the policy's <see cref="IPolicy.MinimumStrengthByCategory"/> requires.
/// 
/// Determinism guarantee: for the same policy + capabilities + context, the engine
/// must always produce the same result, regardless of capability input ordering.
/// This is achieved through deterministic tie-breaking rules (max strength, then
/// lexicographic provider ID, then lexicographic algorithm ID).
/// 
/// Fail-closed: if no candidate satisfies all constraints for a required category,
/// selection throws rather than silently omitting the category.
/// 
/// Thread-safety: implementations must be free of shared mutable state. The canonical
/// implementation (<see cref="Selection.AlgorithmSelector"/>) is purely functional —
/// all state is derived from the method parameters.
/// </summary>
public interface ISelectionEngine
{
    /// <summary>
    /// Selects the best algorithm per required category, given the policy, available capabilities,
    /// and contextual constraints.
    /// </summary>
    /// <param name="policy">Immutable policy snapshot governing the selection.</param>
    /// <param name="capabilities">All algorithm descriptors offered by all trusted providers.</param>
    /// <param name="context">Non-secret selection context (tenant, profile, FIPS override).</param>
    /// <returns>A dictionary mapping each required category to its winning algorithm descriptor.</returns>
    /// <exception cref="Selection.SelectionFailedException">
    /// Thrown when no candidate satisfies the constraints for a required category (fail-closed).
    /// </exception>
    ImmutableDictionary<AlgorithmCategory, AlgorithmDescriptor> Select(
        IPolicy policy,
        ImmutableArray<AlgorithmDescriptor> capabilities,
        in SelectionContext context);
}
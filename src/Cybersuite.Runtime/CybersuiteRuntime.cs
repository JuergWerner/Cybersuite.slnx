using System.Collections.Immutable;
using System.Security.Cryptography;
using Cybersuite.Abstractions;
using Cybersuite.Compliance;
using Cybersuite.ProviderHost;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cybersuite.Runtime;

public sealed class CybersuiteRuntime : IAsyncDisposable
{
    private readonly ProviderHost.ProviderHost _providerHost;
    private readonly ISelectionEngine _selectionEngine;
    private readonly RuntimeOptions _options;
    private readonly IRuntimeAuditSink _auditSink;
    private readonly IComplianceGate _complianceGate;

    private readonly SemaphoreSlim _lifecycle = new(1, 1);
    private RuntimeScope? _currentScope;

    public CybersuiteRuntime(
        ProviderHost.ProviderHost providerHost,
        ISelectionEngine selectionEngine,
        RuntimeOptions? options = null,
        IRuntimeAuditSink? auditSink = null,
        IComplianceGate? complianceGate = null)
    {
        _providerHost = providerHost ?? throw new ArgumentNullException(nameof(providerHost));
        _selectionEngine = selectionEngine ?? throw new ArgumentNullException(nameof(selectionEngine));
        _options = options ?? RuntimeOptions.Default;
        _auditSink = auditSink ?? NullRuntimeAuditSink.Instance;
        _complianceGate = complianceGate ?? new DualComplianceGate(); // SEC-L-001: Default to DualComplianceGate for proper compliance enforcement
    }

    public async Task<RuntimeScope> InitializeAsync(
        IPolicy policy,
        SelectionContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(policy);

        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RuntimeScope? existing = _currentScope;
            if (existing is not null && SameBinding(existing, policy, context))
            {
                return existing;
            }

            if (existing is not null)
            {
                await _providerHost.StopAsync(cancellationToken).ConfigureAwait(false);
                _currentScope = null;
            }

            ProviderSessionBinding binding = RuntimeBindingFactory.Create(policy, context, _options);

            await _providerHost.StartAsync(binding, cancellationToken).ConfigureAwait(false);

            ProviderRegistrySnapshot snapshot = _providerHost.Snapshot;
            ImmutableArray<AlgorithmDescriptor> capabilities = ProviderRegistryFlattener.FlattenTrusted(snapshot);

            ImmutableDictionary<AlgorithmCategory, AlgorithmDescriptor> selected =
                _selectionEngine.Select(policy, capabilities, in context);

            ValidateSelectionAgainstCompliance(snapshot, selected, binding.EffectiveCompliance ?? RuntimeBindingFactory.CreateEffectiveComplianceContext(policy, context, _options));

            ImmutableDictionary<AlgorithmCategory, RuntimeSelectionPlanEntry> plan =
                BuildSelectionPlan(snapshot, selected);

            var scope = new RuntimeScope(
                policy: policy,
                context: context,
                sessionBinding: binding,
                registrySnapshot: snapshot,
                selectionPlan: plan);

            _currentScope = scope;

            if (_options.EmitAuditEvents)
            {
                await _auditSink.WriteAsync(
                    RuntimeAuditEvent.CreateInitialized(scope),
                    cancellationToken).ConfigureAwait(false);
            }

            return scope;
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public RuntimeScope GetCurrentScope()
    {
        RuntimeScope? scope = Interlocked.CompareExchange(ref _currentScope, null, null);
        if (scope is null)
            throw new InvalidOperationException("Runtime has not been initialized.");

        return scope;
    }

    public IProviderSession OpenProviderSession(ProviderId providerId)
    {
        RuntimeScope scope = GetCurrentScope();

        byte[] boundPolicyHash = scope.SessionBinding.PolicyHashSha384.ToArray();

        return _providerHost.OpenSession(
            providerId,
            new ProviderSessionOptions(
                FipsRequired: scope.SessionBinding.FipsRequired,
                TenantId: scope.Context.TenantId,
                BoundPolicyHash: boundPolicyHash,
                EffectiveCompliance: scope.SessionBinding.EffectiveCompliance),
            _complianceGate);
    }

    public IProviderSession OpenSelectedSession(AlgorithmCategory category)
    {
        RuntimeScope scope = GetCurrentScope();

        if (!scope.SelectionPlan.TryGetValue(category, out RuntimeSelectionPlanEntry? planEntry))
            throw new InvalidOperationException($"No selected algorithm exists for category '{category}'.");

        return OpenProviderSession(planEntry.ProviderId);
    }

    public async Task ShutdownAsync(CancellationToken cancellationToken)
    {
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            RuntimeScope? scope = _currentScope;

            await _providerHost.StopAsync(cancellationToken).ConfigureAwait(false);
            _currentScope = null;

            if (_options.EmitAuditEvents)
            {
                await _auditSink.WriteAsync(
                    RuntimeAuditEvent.CreateShutdown(scope),
                    cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _lifecycle.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            if (_options.StopProviderHostOnDispose)
            {
                RuntimeScope? scope = _currentScope;
                await _providerHost.StopAsync(CancellationToken.None).ConfigureAwait(false);
                _currentScope = null;

                if (_options.EmitAuditEvents)
                {
                    await _auditSink.WriteAsync(
                        RuntimeAuditEvent.CreateShutdown(scope),
                        CancellationToken.None).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            _lifecycle.Release();
            _lifecycle.Dispose();
        }
    }

    private void ValidateSelectionAgainstCompliance(
        ProviderRegistrySnapshot snapshot,
        ImmutableDictionary<AlgorithmCategory, AlgorithmDescriptor> selected,
        EffectiveComplianceContext effectiveCompliance)
    {
        foreach (var kv in selected)
        {
            AlgorithmDescriptor descriptor = kv.Value;

            if (!snapshot.Providers.TryGetValue(descriptor.Provider, out ProviderRecord? record))
                throw new InvalidOperationException($"Selected provider '{descriptor.Provider.Value}' is missing from the registry snapshot.");

            ComplianceDecision decision = _complianceGate.Evaluate(
                descriptor,
                record.Metadata,
                effectiveCompliance);

            if (!decision.IsAllowed)
            {
                throw new InvalidOperationException(
                    $"Compliance gate rejected selection for category '{kv.Key}': {decision.Reason}");
            }
        }
    }

    private static ImmutableDictionary<AlgorithmCategory, RuntimeSelectionPlanEntry> BuildSelectionPlan(
        ProviderRegistrySnapshot snapshot,
        ImmutableDictionary<AlgorithmCategory, AlgorithmDescriptor> selected)
    {
        var builder = ImmutableDictionary.CreateBuilder<AlgorithmCategory, RuntimeSelectionPlanEntry>();

        foreach (var kv in selected)
        {
            AlgorithmCategory category = kv.Key;
            AlgorithmDescriptor descriptor = kv.Value;

            if (!snapshot.Providers.TryGetValue(descriptor.Provider, out ProviderRecord? record))
            {
                throw new InvalidOperationException(
                    $"Selection returned provider '{descriptor.Provider.Value}' not present in ProviderRegistrySnapshot.");
            }

            builder[category] = new RuntimeSelectionPlanEntry
            {
                Category = category,
                AlgorithmId = descriptor.Id,
                ProviderId = descriptor.Provider,
                SecurityMode = descriptor.SecurityMode,
                Strength = descriptor.Strength,
                HybridStrength = descriptor.HybridStrength,
                IsFipsApproved = descriptor.IsFipsApproved,
                ParameterSetId = descriptor.ParameterSetId,
                OperationalMaturity = descriptor.OperationalMaturity,
                EncodingProfile = descriptor.EncodingProfile,
                ProviderVersion = record.Metadata.Identity.Version,
                ProviderIsExperimental = record.Metadata.IsExperimental,
                ProviderFipsBoundaryDeclared = record.FipsBoundaryDeclared
            };
        }

        return builder.ToImmutable();
    }

    private static bool SameBinding(RuntimeScope scope, IPolicy policy, SelectionContext context)
    {
        if (!FixedTimePolicyHashEquals(scope.SessionBinding.PolicyHashSha384, policy.PolicyHash.Span))
            return false;

        if (!string.Equals(scope.Context.TenantId, context.TenantId, StringComparison.Ordinal))
            return false;

        if (scope.Context.Profile != context.Profile)
            return false;

        if (scope.Context.ForceFips != context.ForceFips)
            return false;

        return true;
    }

    private static bool FixedTimePolicyHashEquals(ImmutableArray<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.IsDefaultOrEmpty || left.Length != 48 || right.Length != 48)
            return false;

        byte[] leftBytes = left.ToArray();
        bool equal = CryptographicOperations.FixedTimeEquals(leftBytes, right);

        CryptographicOperations.ZeroMemory(leftBytes);
        return equal;
    }
}
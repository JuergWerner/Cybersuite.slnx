using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.Abstractions;
using Cybersuite.Compliance;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.ProviderHost.Discovery;
using Cybersuite.ProviderHost.Launch;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Central orchestrator for the provider lifecycle within the Cybersuite architecture.
/// Coordinates the full pipeline: discovery → trust evaluation → launch → handshake →
/// capability negotiation → registry population. Maintains a thread-safe registry of
/// active providers and their session state, and implements <see cref="IAsyncDisposable"/>
/// to cleanly shut down all provider connections.
///
/// Wave 2 turns startup into an explicit start transaction with a combined deadline,
/// rollback semantics, failure journaling, and real launch-context propagation.
/// </summary>
public sealed class ProviderHost : IAsyncDisposable
{
    private readonly ProviderHostOptions _options;
    private readonly IProviderDiscovery _discovery;
    private readonly IProviderTrustEvaluator _trustEvaluator;
    private readonly IProviderLauncher _launcher;
    private readonly ICapabilitySnapshotDecoder _capabilityDecoder;
    private readonly ILogger<ProviderHost> _logger;

    private readonly ProviderRegistry _registry = new();
    private readonly ConcurrentDictionary<ProviderId, LiveProviderSessionState> _sessions = new();
    private readonly SemaphoreSlim _lifecycle = new(1, 1);

    private int _hostState = (int)ProviderHostLifecycleState.Stopped;
    private ProviderStartJournal _lastStartJournal = ProviderStartJournal.Empty;
    private ProviderFailureJournal _failureJournal = ProviderFailureJournal.Empty;

    public ProviderHost(
        ProviderHostOptions options,
        IProviderDiscovery discovery,
        IProviderTrustEvaluator trustEvaluator,
        IProviderLauncher launcher,
        ICapabilitySnapshotDecoder capabilityDecoder,
        ILogger<ProviderHost>? logger = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _discovery = discovery ?? throw new ArgumentNullException(nameof(discovery));
        _trustEvaluator = trustEvaluator ?? throw new ArgumentNullException(nameof(trustEvaluator));
        _launcher = launcher ?? throw new ArgumentNullException(nameof(launcher));
        _capabilityDecoder = capabilityDecoder ?? throw new ArgumentNullException(nameof(capabilityDecoder));
        _logger = logger ?? NullLogger<ProviderHost>.Instance;
    }

    public ProviderRegistrySnapshot Snapshot => _registry.Snapshot;

    public ProviderHostLifecycleState LifecycleState =>
        (ProviderHostLifecycleState)Volatile.Read(ref _hostState);

    public ProviderStartJournal LastStartJournal => Volatile.Read(ref _lastStartJournal);

    public ProviderFailureJournal FailureJournal => Volatile.Read(ref _failureJournal);

    public async Task StartAsync(ProviderSessionBinding binding, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(binding);
        binding.Validate();

        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposed();

            if (LifecycleState != ProviderHostLifecycleState.Stopped)
                throw new InvalidOperationException($"ProviderHost cannot start while in state '{LifecycleState}'.");

            Volatile.Write(ref _hostState, (int)ProviderHostLifecycleState.Starting);
            Volatile.Write(ref _lastStartJournal, ProviderStartJournal.Empty);
            Volatile.Write(ref _failureJournal, ProviderFailureJournal.Empty);

            var transactions = ImmutableArray.CreateBuilder<ProviderStartTransaction>();
            var failures = ImmutableArray.CreateBuilder<ProviderStartTransaction>();
            var pendingReady = new List<PendingProviderCommit>();

            try
            {
                await foreach (var package in _discovery.DiscoverAsync(cancellationToken).ConfigureAwait(false))
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    ProviderLaunchContext launchContext = BuildLaunchContext(binding);
                    ProviderStartResult result = await StartProviderAsync(package, binding, launchContext, cancellationToken).ConfigureAwait(false);

                    transactions.Add(result.Transaction);
                    if (ShouldJournalFailure(result.Transaction.State))
                        failures.Add(result.Transaction);

                    if (result.PendingCommit is not null)
                        pendingReady.Add(result.PendingCommit);
                }

                CommitReadyProviders(pendingReady);

                Volatile.Write(ref _lastStartJournal, new ProviderStartJournal(transactions.ToImmutable()));
                Volatile.Write(ref _failureJournal, new ProviderFailureJournal(failures.ToImmutable()));
                Volatile.Write(ref _hostState, (int)ProviderHostLifecycleState.Started);
            }
            catch
            {
                await RollbackPendingAsync(pendingReady).ConfigureAwait(false);

                Volatile.Write(ref _lastStartJournal, new ProviderStartJournal(transactions.ToImmutable()));
                Volatile.Write(ref _failureJournal, new ProviderFailureJournal(failures.ToImmutable()));
                Volatile.Write(ref _hostState, (int)ProviderHostLifecycleState.Stopped);
                throw;
            }
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public IProviderSession OpenSession(ProviderId providerId, ProviderSessionOptions options, IComplianceGate? complianceGate = null)
    {
        _lifecycle.Wait();
        try
        {
            ThrowIfDisposed();

            if (LifecycleState != ProviderHostLifecycleState.Started)
                throw new InvalidOperationException("ProviderHost is not started.");

            if (!_sessions.TryGetValue(providerId, out var state))
                throw new InvalidOperationException($"No active provider session exists for provider '{providerId.Value}'.");

            if (!Snapshot.Providers.TryGetValue(providerId, out var record))
                throw new InvalidOperationException($"Provider '{providerId.Value}' not found in registry snapshot.");

            return new ProviderRpcSession(state, record, options, complianceGate);
        }
        finally
        {
            _lifecycle.Release();
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await _lifecycle.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ProviderHostLifecycleState state = LifecycleState;
            if (state == ProviderHostLifecycleState.Disposed || state == ProviderHostLifecycleState.Stopped)
                return;

            Volatile.Write(ref _hostState, (int)ProviderHostLifecycleState.Stopping);

            var sessions = new List<KeyValuePair<ProviderId, LiveProviderSessionState>>();
            foreach (var kv in _sessions)
                sessions.Add(kv);

            foreach (var kv in sessions)
                kv.Value.MarkStopping();

            foreach (var providerId in _sessions.Keys)
            {
                _sessions.TryRemove(providerId, out _);
                _registry.TryRemove(providerId);
            }

            foreach (var kv in sessions)
            {
                await ShutdownAndDisposeAsync(kv.Key, kv.Value).ConfigureAwait(false);
            }

            Volatile.Write(ref _hostState, (int)ProviderHostLifecycleState.Stopped);
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
            if (LifecycleState == ProviderHostLifecycleState.Disposed)
                return;

            Volatile.Write(ref _hostState, (int)ProviderHostLifecycleState.Stopping);

            var sessions = new List<KeyValuePair<ProviderId, LiveProviderSessionState>>();
            foreach (var kv in _sessions)
                sessions.Add(kv);

            foreach (var kv in sessions)
                kv.Value.MarkStopping();

            foreach (var providerId in _sessions.Keys)
            {
                _sessions.TryRemove(providerId, out _);
                _registry.TryRemove(providerId);
            }

            foreach (var kv in sessions)
                await SafeDisposeAsync(kv.Value.Connection).ConfigureAwait(false);

            Volatile.Write(ref _hostState, (int)ProviderHostLifecycleState.Disposed);
        }
        finally
        {
            _lifecycle.Release();
            _lifecycle.Dispose();
        }
    }

    private async Task<ProviderStartResult> StartProviderAsync(
        ProviderPackage package,
        ProviderSessionBinding binding,
        ProviderLaunchContext launchContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(package);

        var transaction = new ProviderStartTransaction(
            Package: package,
            LaunchContext: launchContext,
            State: ProviderLifecycleState.Discovered,
            ReasonCode: null,
            Exception: null,
            StartedAt: DateTimeOffset.UtcNow,
            FinishedAt: null);

        IProviderConnection? connection = null;
        bool connectionLaunched = false;
        ProviderTrustDecision trustDecision = default;
        ProviderAttestationVerificationResult attestationDecision =
            ProviderAttestationVerificationResult.Accepted(ProviderAttestationStatus.NotRequired, "Attestation not yet evaluated.");

        try
        {
            trustDecision = await _trustEvaluator.EvaluateAsync(package, _options, cancellationToken).ConfigureAwait(false);
            if (!trustDecision.IsTrusted)
            {
                string trustRejectReason = trustDecision.ReleaseStatus switch
                {
                    ProviderReleaseStatus.Missing => ProviderHostReasonCodes.ReleaseBundleMissing,
                    ProviderReleaseStatus.Rejected => ProviderHostReasonCodes.ReleaseVerificationFailed,
                    _ => trustDecision.ProvenanceStatus switch
                    {
                        ProviderProvenanceStatus.Missing => ProviderHostReasonCodes.ProvenanceBundleMissing,
                        ProviderProvenanceStatus.Rejected => ProviderHostReasonCodes.ProvenanceVerificationFailed,
                        _ => $"{ProviderHostReasonCodes.TrustRejected}:{trustDecision.Reason}"
                    }
                };

                transaction = Complete(transaction, ProviderLifecycleState.TrustRejected, trustRejectReason);
                LogRejected(transaction);
                return new ProviderStartResult(transaction, null);
            }

            transaction = transaction with { State = ProviderLifecycleState.TrustAccepted };

            bool experimentalAllowed = binding.EffectiveCompliance?.ExperimentalAllowed ?? binding.ExperimentalAllowed;
            if (!experimentalAllowed && package.Manifest.IsExperimental)
            {
                transaction = Complete(transaction, ProviderLifecycleState.TrustRejected, ProviderHostReasonCodes.ExperimentalProviderRejected);
                LogRejected(transaction);
                return new ProviderStartResult(transaction, null);
            }

            if (!LaunchContextAdmitsPackage(package, launchContext, out string? rejectReason))
            {
                transaction = Complete(transaction, ProviderLifecycleState.TrustRejected, rejectReason);
                LogRejected(transaction);
                return new ProviderStartResult(transaction, null);
            }

            using var startCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            startCts.CancelAfter(_options.ProviderStartupTimeout);

            transaction = transaction with { State = ProviderLifecycleState.Launching };
            connection = await _launcher.LaunchAsync(package, launchContext, startCts.Token).ConfigureAwait(false);
            connectionLaunched = true;
            transaction = transaction with { State = ProviderLifecycleState.Launched };

            var clientHello = BuildClientHello(binding, package.Manifest.ProviderId);

            transaction = transaction with { State = ProviderLifecycleState.Handshaking };
            ProviderHello providerHello = await connection.HandshakeAsync(clientHello, startCts.Token).ConfigureAwait(false);

            if (!providerHello.Identity.ProviderId.Equals(package.Manifest.ProviderId))
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.ProviderIdMismatch).ConfigureAwait(false);

            if (!experimentalAllowed && providerHello.IsExperimental)
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.ExperimentalProviderRejected).ConfigureAwait(false);

            if (!ComplianceEnvelopeMatchesManifest(package.Manifest, providerHello))
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.ManifestHelloMismatch).ConfigureAwait(false);

            if (launchContext.ExpectedProviderId is ProviderId expectedProviderId &&
                !providerHello.Identity.ProviderId.Equals(expectedProviderId))
            {
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.ExpectedProviderMismatch).ConfigureAwait(false);
            }

            if (launchContext.ExpectedBuildHashSha256 is { } expectedBuildHash &&
                !FixedTimeHashEqualsHex(providerHello.Identity.BuildHash, expectedBuildHash))
            {
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.ExpectedBuildHashMismatch).ConfigureAwait(false);
            }

            attestationDecision = await _options.AttestationVerifier
                .VerifyAsync(package, providerHello, binding, _options, startCts.Token)
                .ConfigureAwait(false);

            if (!attestationDecision.IsAccepted)
            {
                string attestationReason = attestationDecision.Status == ProviderAttestationStatus.Missing
                    ? ProviderHostReasonCodes.AttestationRequiredMissing
                    : ProviderHostReasonCodes.AttestationVerificationFailed;

                return await RollbackAsync(transaction, connection, attestationReason).ConfigureAwait(false);
            }

            var session = LiveProviderSessionState.Create(connection, clientHello, providerHello, launchContext.TransportBudget);

            CapabilityResponse capabilityResponse = await connection.GetCapabilitiesAsync(
                new CapabilityRequest(session.NewRequestHeader(OopMessageType.CapabilityRequest)),
                startCts.Token).ConfigureAwait(false);

            try
            {
                OopTransportBudgetGuard.EnsureCapabilitySnapshotWithinBudget(
                    launchContext.TransportBudget,
                    capabilityResponse.CapabilityCanonicalBytes.Length);
            }
            catch (OopTransportBudgetExceededException ex)
            {
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.CapabilityBudgetExceeded, ex).ConfigureAwait(false);
            }

            if (!session.ValidatePolicyHash(binding.PolicyHashSha384.AsSpan()))
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.PolicyHashMismatch).ConfigureAwait(false);

            if (!session.ValidatePolicyHash(clientHello.PolicyHashSha384.Span))
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.PolicyHashMismatch).ConfigureAwait(false);

            if (!OopFixedTime.FixedTimeEqualsSha384(
                    providerHello.CapabilityHashSha384.Span,
                    capabilityResponse.CapabilityHashSha384.Span))
            {
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.CapabilityHashMismatch).ConfigureAwait(false);
            }

            CapabilitySnapshot capabilities;
            try
            {
                capabilities = _capabilityDecoder.Decode(
                    providerHello.Identity,
                    capabilityResponse.CapabilityCanonicalBytes.Span,
                    capabilityResponse.CapabilityHashSha384.Span);
            }
            catch (Exception ex)
            {
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.CapabilityDecodeFailed, ex).ConfigureAwait(false);
            }

            if (!BoundarySatisfies(providerHello.ComplianceEnvelope.BoundaryClass, launchContext.RequiredBoundaryClass))
            {
                return await RollbackAsync(transaction, connection, ProviderHostReasonCodes.BoundaryRequirementRejected).ConfigureAwait(false);
            }

            transaction = transaction with { State = ProviderLifecycleState.CapabilityVerified };

            var metadata = new ProviderMetadata(
                identity: providerHello.Identity,
                vendor: package.Manifest.Vendor,
                isolationMode: package.Manifest.IsolationMode,
                trustState: ProviderTrustState.Trusted,
                isExperimental: package.Manifest.IsExperimental || providerHello.IsExperimental,
                complianceEnvelope: providerHello.ComplianceEnvelope);

            var record = new ProviderRecord
            {
                Metadata = metadata,
                Capabilities = capabilities,
                TranscriptHashSha384 = session.TranscriptHashSha384,
                ChannelBindingSha384 = session.ChannelBindingSha384,
                ComplianceEnvelope = providerHello.ComplianceEnvelope,
                ProvenanceStatus = trustDecision.ProvenanceStatus,
                ProvenanceSignerFingerprint = trustDecision.ProvenanceSignerFingerprint,
                ReleaseStatus = trustDecision.ReleaseStatus,
                ReleaseRepositoryUri = trustDecision.ReleaseRepositoryUri,
                ReleaseChannel = trustDecision.ReleaseChannel,
                ReleaseSignerFingerprint = trustDecision.ReleaseSignerFingerprint,
                ReleaseManifestSha256Hex = trustDecision.ReleaseManifestSha256Hex,
                ReleaseSbomSha256Hex = trustDecision.ReleaseSbomSha256Hex,
                AttestationStatus = attestationDecision.Status,
                AttestationEvidenceSha256Hex = attestationDecision.EvidenceSha256Hex,
                FipsBoundaryDeclared = providerHello.ComplianceEnvelope.DeclaredValidatedBoundary
            };

            transaction = Complete(transaction, ProviderLifecycleState.Ready, null);
            _logger.LogInformation("Provider {ProviderId} reached Ready.", package.Manifest.ProviderId.Value);
            return new ProviderStartResult(transaction, new PendingProviderCommit(metadata.Identity.ProviderId, session, record));
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            string reasonCode = transaction.State switch
            {
                ProviderLifecycleState.Launching => ProviderHostReasonCodes.LaunchDeadlineExceeded,
                ProviderLifecycleState.Handshaking => ProviderHostReasonCodes.HandshakeDeadlineExceeded,
                _ => ProviderHostReasonCodes.CapabilityDeadlineExceeded
            };

            if (connectionLaunched && connection is not null)
                return await RollbackAsync(transaction, connection, reasonCode, ex).ConfigureAwait(false);

            transaction = Complete(transaction, ProviderLifecycleState.Faulted, reasonCode, ex);
            LogFailed(transaction);
            return new ProviderStartResult(transaction, null);
        }
        catch (Exception ex)
        {
            string reasonCode = transaction.State switch
            {
                ProviderLifecycleState.Launching => ProviderHostReasonCodes.LaunchFailed,
                ProviderLifecycleState.Handshaking => ProviderHostReasonCodes.HandshakeFailed,
                _ => ProviderHostReasonCodes.CapabilityNegotiationFailed
            };

            if (connectionLaunched && connection is not null)
                return await RollbackAsync(transaction, connection, reasonCode, ex).ConfigureAwait(false);

            transaction = Complete(transaction, ProviderLifecycleState.Faulted, reasonCode, ex);
            LogFailed(transaction);
            return new ProviderStartResult(transaction, null);
        }
    }

    private ProviderLaunchContext BuildLaunchContext(ProviderSessionBinding binding)
    {
        EffectiveComplianceContext? effective = binding.EffectiveCompliance;
        ExecutionProfile profile = effective?.Profile ?? binding.ExecutionProfile;

        if (profile != _options.ExecutionProfile)
        {
            throw new InvalidOperationException(
                $"Provider session binding profile '{profile}' does not match host execution profile '{_options.ExecutionProfile}'.");
        }

        RequiredBoundaryClass requiredBoundary = effective?.RequiredBoundaryClass ?? ComputeRequiredBoundaryClass(profile, binding.FipsRequired);
        ProviderSecurityClass targetSecurityClass = requiredBoundary switch
        {
            RequiredBoundaryClass.ValidatedBoundary => ProviderSecurityClass.ValidatedBoundary,
            RequiredBoundaryClass.IsolatedProcess => ProviderSecurityClass.ProductionIsolated,
            _ => ProviderSecurityClass.ReferenceInProcess
        };

        ProviderLaunchContext launchContext = new(
            Profile: profile,
            TargetSecurityClass: targetSecurityClass,
            RequiredBoundaryClass: requiredBoundary,
            TransportBudget: OopTransportBudget.ForProfile(profile, _options.TransportLimits),
            EnableNetworkAccess: _options.EnableNetworkAccess,
            BoundPolicyHashSha384: binding.PolicyHashSha384,
            ExpectedProviderId: binding.ExpectedProviderId,
            ExpectedBuildHashSha256: TryParseHexToImmutable(binding.ExpectedBuildHash));

        launchContext.Validate();
        return launchContext;
    }

    private static RequiredBoundaryClass ComputeRequiredBoundaryClass(ExecutionProfile profile, bool fipsRequired)
    {
        if (fipsRequired)
            return RequiredBoundaryClass.ValidatedBoundary;

        return profile switch
        {
            ExecutionProfile.Dev => RequiredBoundaryClass.None,
            ExecutionProfile.Staging => RequiredBoundaryClass.IsolatedProcess,
            ExecutionProfile.Prod => RequiredBoundaryClass.IsolatedProcess,
            _ => RequiredBoundaryClass.None
        };
    }

    private static ClientHello BuildClientHello(ProviderSessionBinding binding, ProviderId packageProviderId)
    {
        Span<byte> nonce = stackalloc byte[OopConstants.NonceSizeBytes];
        RandomNumberGenerator.Fill(nonce);

        EffectiveComplianceContext? effective = binding.EffectiveCompliance;

        return new ClientHello(
            version: ProtocolVersion.V1_0,
            nonce32: nonce,
            policyHashSha384: binding.PolicyHashSha384.AsSpan(),
            profile: effective?.Profile ?? binding.ExecutionProfile,
            fipsRequired: effective?.EffectiveFipsRequired ?? binding.FipsRequired,
            experimentalAllowed: effective?.ExperimentalAllowed ?? binding.ExperimentalAllowed,
            tenantId: effective?.TenantId ?? binding.TenantId,
            expectedProviderId: (binding.ExpectedProviderId ?? packageProviderId).Value,
            expectedBuildHash: binding.ExpectedBuildHash);
    }

    private static bool ComplianceEnvelopeMatchesManifest(ProviderManifest manifest, ProviderHello providerHello)
    {
        ProviderComplianceEnvelope manifestEnvelope = manifest.ComplianceEnvelope;
        ProviderComplianceEnvelope helloEnvelope = providerHello.ComplianceEnvelope;

        if (manifest.FipsBoundaryDeclared != manifestEnvelope.DeclaredValidatedBoundary)
            return false;

        if (providerHello.FipsBoundaryDeclared != helloEnvelope.DeclaredValidatedBoundary)
            return false;

        return manifestEnvelope.SemanticallyEquals(helloEnvelope);
    }

    private static bool LaunchContextAdmitsPackage(
        ProviderPackage package,
        ProviderLaunchContext launchContext,
        out string? reasonCode)
    {
        reasonCode = null;

        if (launchContext.ExpectedProviderId is ProviderId expectedProviderId &&
            !package.Manifest.ProviderId.Equals(expectedProviderId))
        {
            reasonCode = ProviderHostReasonCodes.ExpectedProviderMismatch;
            return false;
        }

        if (launchContext.ExpectedBuildHashSha256 is { } expectedBuildHash &&
            !ManifestBuildHashMatches(package.Manifest.EntrypointSha256Hex, expectedBuildHash))
        {
            reasonCode = ProviderHostReasonCodes.ExpectedBuildHashMismatch;
            return false;
        }

        ProviderComplianceEnvelope envelope = package.Manifest.ComplianceEnvelope;
        RequiredBoundaryClass actualBoundary = envelope.BoundaryClass;

        if (!ManifestIsolationMatchesEnvelope(package.Manifest, out string? isolationReason))
        {
            reasonCode = isolationReason;
            return false;
        }

        if (!BoundarySatisfies(actualBoundary, launchContext.RequiredBoundaryClass))
        {
            reasonCode = ProviderHostReasonCodes.BoundaryRequirementRejected;
            return false;
        }

        if (launchContext.Profile != ExecutionProfile.Dev &&
            envelope.SecurityClass == ProviderSecurityClass.ReferenceInProcess)
        {
            reasonCode = ProviderHostReasonCodes.ReferenceProviderRejectedOutsideDev;
            return false;
        }

        if (launchContext.TargetSecurityClass == ProviderSecurityClass.ProductionIsolated &&
            package.Manifest.IsolationMode == ProviderIsolationMode.InProcess)
        {
            reasonCode = ProviderHostReasonCodes.ManifestIsolationEnvelopeMismatch;
            return false;
        }

        return true;
    }

    private static bool ManifestIsolationMatchesEnvelope(ProviderManifest manifest, out string? reasonCode)
    {
        reasonCode = null;
        ProviderComplianceEnvelope envelope = manifest.ComplianceEnvelope;

        switch (manifest.IsolationMode)
        {
            case ProviderIsolationMode.InProcess:
                if (envelope.SecurityClass != ProviderSecurityClass.ReferenceInProcess || envelope.BoundaryClass != RequiredBoundaryClass.None)
                {
                    reasonCode = ProviderHostReasonCodes.ManifestIsolationEnvelopeMismatch;
                    return false;
                }
                return true;

            case ProviderIsolationMode.OutOfProcess:
                if (envelope.SecurityClass == ProviderSecurityClass.ReferenceInProcess || envelope.BoundaryClass < RequiredBoundaryClass.IsolatedProcess)
                {
                    reasonCode = ProviderHostReasonCodes.ManifestIsolationEnvelopeMismatch;
                    return false;
                }
                return true;

            case ProviderIsolationMode.HardwareBoundary:
                if (envelope.BoundaryClass < RequiredBoundaryClass.IsolatedProcess)
                {
                    reasonCode = ProviderHostReasonCodes.ManifestIsolationEnvelopeMismatch;
                    return false;
                }
                return true;

            default:
                reasonCode = ProviderHostReasonCodes.ManifestIsolationEnvelopeMismatch;
                return false;
        }
    }

    private static bool BoundarySatisfies(RequiredBoundaryClass actual, RequiredBoundaryClass required)
        => (int)actual >= (int)required;

    private static bool ShouldJournalFailure(ProviderLifecycleState state)
        => state is ProviderLifecycleState.TrustRejected
            or ProviderLifecycleState.Faulted
            or ProviderLifecycleState.RolledBack;

    private async Task<ProviderStartResult> RollbackAsync(
        ProviderStartTransaction transaction,
        IProviderConnection connection,
        string reasonCode,
        Exception? exception = null)
    {
        transaction = Complete(transaction, ProviderLifecycleState.RolledBack, reasonCode, exception);
        await SafeDisposeAsync(connection).ConfigureAwait(false);
        LogFailed(transaction);
        return new ProviderStartResult(transaction, null);
    }

    private void CommitReadyProviders(IReadOnlyList<PendingProviderCommit> pendingReady)
    {
        for (int i = 0; i < pendingReady.Count; i++)
        {
            PendingProviderCommit pending = pendingReady[i];
            _registry.Upsert(pending.ProviderId, pending.Record);
            _sessions[pending.ProviderId] = pending.Session;
        }
    }

    private async Task RollbackPendingAsync(IReadOnlyList<PendingProviderCommit> pendingReady)
    {
        for (int i = 0; i < pendingReady.Count; i++)
        {
            pendingReady[i].Session.MarkStopping();
            await SafeDisposeAsync(pendingReady[i].Session.Connection).ConfigureAwait(false);
        }
    }

    private async Task ShutdownAndDisposeAsync(ProviderId providerId, LiveProviderSessionState session)
    {
        using var stopCts = new CancellationTokenSource(_options.ProviderShutdownTimeout);

        try
        {
            await session.Connection.ShutdownAsync(
                new ShutdownRequest(session.NewRequestHeader(OopMessageType.ShutdownRequest), graceful: true),
                stopCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Graceful shutdown failed for provider {ProviderId}; continuing with dispose.", providerId.Value);
        }

        await SafeDisposeAsync(session.Connection).ConfigureAwait(false);
    }

    private static ProviderStartTransaction Complete(
        ProviderStartTransaction transaction,
        ProviderLifecycleState terminalState,
        string? reasonCode,
        Exception? exception = null)
        => transaction with
        {
            State = terminalState,
            ReasonCode = reasonCode,
            Exception = exception,
            FinishedAt = DateTimeOffset.UtcNow
        };

    private void LogRejected(ProviderStartTransaction transaction)
    {
        _logger.LogWarning(
            "Provider {ProviderId} rejected during startup with state {State} and reason {ReasonCode}.",
            transaction.ProviderId.Value,
            transaction.State,
            transaction.ReasonCode);
    }

    private void LogFailed(ProviderStartTransaction transaction)
    {
        if (transaction.Exception is null)
        {
            _logger.LogWarning(
                "Provider {ProviderId} ended startup in state {State} with reason {ReasonCode}.",
                transaction.ProviderId.Value,
                transaction.State,
                transaction.ReasonCode);
            return;
        }

        _logger.LogWarning(
            transaction.Exception,
            "Provider {ProviderId} ended startup in state {State} with reason {ReasonCode}.",
            transaction.ProviderId.Value,
            transaction.State,
            transaction.ReasonCode);
    }

    private void ThrowIfDisposed()
    {
        if (LifecycleState == ProviderHostLifecycleState.Disposed)
            throw new ObjectDisposedException(nameof(ProviderHost), ProviderHostReasonCodes.HostDisposed);
    }

    private static async Task SafeDisposeAsync(IProviderConnection connection)
    {
        try
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private static bool FixedTimeHashEqualsHex(string actualHex, ImmutableArray<byte> expectedHash)
    {
        if (!TryParseHex(actualHex, out byte[] actualBytes))
            return false;

        try
        {
            if (expectedHash.IsDefaultOrEmpty || expectedHash.Length != 32 || actualBytes.Length != 32)
                return false;

            return CryptographicOperations.FixedTimeEquals(actualBytes, expectedHash.AsSpan());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualBytes);
        }
    }

    private static bool ManifestBuildHashMatches(string? manifestHex, ImmutableArray<byte> expectedHash)
    {
        if (string.IsNullOrWhiteSpace(manifestHex))
            return false;

        return FixedTimeHashEqualsHex(manifestHex, expectedHash);
    }

    private static ImmutableArray<byte>? TryParseHexToImmutable(string? hex)
    {
        if (!TryParseHex(hex, out byte[] bytes))
            return null;

        try
        {
            if (bytes.Length != 32)
                return null;

            return ImmutableArray.CreateRange(bytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    private static bool TryParseHex(string? hex, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();

        if (string.IsNullOrWhiteSpace(hex))
            return false;

        string normalized = hex.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[2..];

        if (normalized.Length == 0 || (normalized.Length % 2) != 0)
            return false;

        byte[] buffer = new byte[normalized.Length / 2];
        for (int i = 0; i < buffer.Length; i++)
        {
            int hi = ParseNibble(normalized[2 * i]);
            int lo = ParseNibble(normalized[2 * i + 1]);
            if (hi < 0 || lo < 0)
            {
                CryptographicOperations.ZeroMemory(buffer);
                return false;
            }

            buffer[i] = (byte)((hi << 4) | lo);
        }

        bytes = buffer;
        return true;

        static int ParseNibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    }

    private sealed record PendingProviderCommit(
        ProviderId ProviderId,
        LiveProviderSessionState Session,
        ProviderRecord Record);

    private sealed record ProviderStartResult(
        ProviderStartTransaction Transaction,
        PendingProviderCommit? PendingCommit);
}

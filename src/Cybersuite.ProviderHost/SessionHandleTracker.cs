using System;
using System.Collections.Generic;
using Cybersuite.Abstractions;

namespace Cybersuite.ProviderHost;

/// <summary>
/// F2/F3-FIX: Tracks opaque handles created during a single <see cref="ProviderRpcSession"/> lifetime.
/// Provides thread-safe registration, ownership validation, and bulk drain for session-end cleanup.
///
/// Design rationale (audit finding F2):
/// Handles carry only <c>(ProviderId, Guid)</c> — no session identity. Without server-side
/// tracking, a handle leaked between sessions on the same provider connection can be reused.
/// This tracker binds handles to a session and rejects cross-session use fail-closed.
///
/// Auto-cleanup (audit finding F3):
/// On session dispose, <see cref="DrainAll"/> returns all still-tracked handles so the session
/// can destroy them before releasing provider resources.
/// </summary>
internal sealed class SessionHandleTracker
{
    private readonly HashSet<Guid> _privateKeys = new();
    private readonly HashSet<Guid> _secretKeys = new();
    private readonly HashSet<Guid> _sharedSecrets = new();
    private readonly object _gate = new();
    private bool _drained;

    // ── Track ──────────────────────────────────────────────

    /// <summary>Registers a newly created private key handle with this session.</summary>
    public void Track(PrivateKeyHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDrained();
            _privateKeys.Add(handle.Value);
        }
    }

    /// <summary>Registers a newly created secret key handle with this session.</summary>
    public void Track(SecretKeyHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDrained();
            _secretKeys.Add(handle.Value);
        }
    }

    /// <summary>Registers a newly created shared secret handle with this session.</summary>
    public void Track(SharedSecretHandle handle)
    {
        lock (_gate)
        {
            ThrowIfDrained();
            _sharedSecrets.Add(handle.Value);
        }
    }

    // ── Validate ───────────────────────────────────────────

    /// <summary>
    /// Validates that a private key handle belongs to this session. Throws fail-closed on mismatch.
    /// </summary>
    public void ValidateOwnership(PrivateKeyHandle handle, string operation)
    {
        lock (_gate)
        {
            if (!_privateKeys.Contains(handle.Value))
                throw new InvalidOperationException(
                    $"{operation} rejected: PrivateKeyHandle '{handle.Value}' is not owned by this session.");
        }
    }

    /// <summary>
    /// Validates that a secret key handle belongs to this session. Throws fail-closed on mismatch.
    /// </summary>
    public void ValidateOwnership(SecretKeyHandle handle, string operation)
    {
        lock (_gate)
        {
            if (!_secretKeys.Contains(handle.Value))
                throw new InvalidOperationException(
                    $"{operation} rejected: SecretKeyHandle '{handle.Value}' is not owned by this session.");
        }
    }

    /// <summary>
    /// Validates that a shared secret handle belongs to this session. Throws fail-closed on mismatch.
    /// </summary>
    public void ValidateOwnership(SharedSecretHandle handle, string operation)
    {
        lock (_gate)
        {
            if (!_sharedSecrets.Contains(handle.Value))
                throw new InvalidOperationException(
                    $"{operation} rejected: SharedSecretHandle '{handle.Value}' is not owned by this session.");
        }
    }

    // ── Untrack ────────────────────────────────────────────

    /// <summary>Removes a private key handle from tracking (e.g., after explicit Destroy).</summary>
    public void Untrack(PrivateKeyHandle handle)
    {
        lock (_gate)
            _privateKeys.Remove(handle.Value);
    }

    /// <summary>Removes a secret key handle from tracking (e.g., after explicit Destroy).</summary>
    public void Untrack(SecretKeyHandle handle)
    {
        lock (_gate)
            _secretKeys.Remove(handle.Value);
    }

    /// <summary>Removes a shared secret handle from tracking (e.g., after explicit Destroy).</summary>
    public void Untrack(SharedSecretHandle handle)
    {
        lock (_gate)
            _sharedSecrets.Remove(handle.Value);
    }

    // ── Drain ──────────────────────────────────────────────

    /// <summary>
    /// Atomically returns all tracked handles and marks the tracker as drained.
    /// Subsequent Track calls will throw. Used during session dispose for auto-cleanup.
    /// </summary>
    public TrackedHandles DrainAll()
    {
        lock (_gate)
        {
            _drained = true;
            var result = new TrackedHandles(
                new List<Guid>(_privateKeys),
                new List<Guid>(_secretKeys),
                new List<Guid>(_sharedSecrets));

            _privateKeys.Clear();
            _secretKeys.Clear();
            _sharedSecrets.Clear();

            return result;
        }
    }

    /// <summary>Whether this tracker has been drained (session disposed).</summary>
    public bool IsDrained
    {
        get { lock (_gate) return _drained; }
    }

    private void ThrowIfDrained()
    {
        if (_drained)
            throw new ObjectDisposedException(nameof(SessionHandleTracker),
                "Cannot track handles on a disposed session.");
    }

    /// <summary>
    /// Snapshot of all handle GUIDs that were tracked at drain time.
    /// </summary>
    internal readonly record struct TrackedHandles(
        IReadOnlyList<Guid> PrivateKeys,
        IReadOnlyList<Guid> SecretKeys,
        IReadOnlyList<Guid> SharedSecrets);
}

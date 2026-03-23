using System;
using System.Collections.Immutable;
using System.Threading;
using Cybersuite.Abstractions;
using Cybersuite.Compliance;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Messages;

namespace Cybersuite.ProviderHost;

/// <summary>
/// Provider-neutral runtime session backed by an OOP-capable provider connection.
/// Implements the existing abstractions without changing the architecture.
///
/// Accessibility note:
/// This type is public because it implements the public runtime-facing <see cref="IProviderSession"/>.
/// Its constructor is intentionally internal because it depends on the internal
/// <see cref="LiveProviderSessionState"/> coordination object and must only be created by ProviderHost.
/// </summary>
public sealed class ProviderRpcSession : IProviderSession
{
    private readonly LiveProviderSessionState _state;
    private readonly ProviderRecord _record;
    private readonly EffectiveComplianceContext? _effectiveCompliance;
    private readonly IComplianceGate? _complianceGate;
    private readonly SessionHandleTracker _tracker = new();
    private int _disposed;

    internal ProviderRpcSession(
        LiveProviderSessionState state,
        ProviderRecord record,
        ProviderSessionOptions options,
        IComplianceGate? complianceGate = null)
    {
        _state = state ?? throw new ArgumentNullException(nameof(state));
        _record = record ?? throw new ArgumentNullException(nameof(record));
        _effectiveCompliance = options.EffectiveCompliance;
        _complianceGate = complianceGate;

        if (options.BoundPolicyHash.Length != 48)
            throw new ArgumentException("BoundPolicyHash must be 48 bytes (SHA-384).", nameof(options));

        if (!_state.ValidatePolicyHash(options.BoundPolicyHash.Span))
            throw new InvalidOperationException("Provider session binding does not match the current policy hash.");

        if (_effectiveCompliance is not null &&
            !BoundarySatisfies(_record.Metadata.ComplianceEnvelope.BoundaryClass, _effectiveCompliance.RequiredBoundaryClass))
        {
            throw new InvalidOperationException(
                $"Required boundary '{_effectiveCompliance.RequiredBoundaryClass}' cannot be satisfied by provider boundary '{_record.Metadata.ComplianceEnvelope.BoundaryClass}'.");
        }

        if (_effectiveCompliance is null && options.FipsRequired && !_record.FipsBoundaryDeclared)
            throw new InvalidOperationException("FIPS-required session cannot be opened on a provider without declared FIPS boundary.");
    }

    public ProviderId ProviderId => _record.Metadata.Identity.ProviderId;

    public bool FipsBoundaryActive => _record.FipsBoundaryDeclared;

    public ImmutableArray<AlgorithmDescriptor> Capabilities => _record.Capabilities.Algorithms;

    public IKemService GetKem(AlgorithmId algorithmId)
    {
        ThrowIfDisposed();
        AlgorithmDescriptor descriptor = Resolve(algorithmId, AlgorithmCategory.KeyEncapsulation);
        return new KemProxy(_state, descriptor, _tracker);
    }

    public ISignatureService GetSignature(AlgorithmId algorithmId)
    {
        ThrowIfDisposed();
        AlgorithmDescriptor descriptor = Resolve(algorithmId, AlgorithmCategory.Signature);
        return new SignatureProxy(_state, descriptor, _tracker);
    }

    public IAeadService GetAead(AlgorithmId algorithmId)
    {
        ThrowIfDisposed();
        AlgorithmDescriptor descriptor = Resolve(algorithmId, AlgorithmCategory.SymmetricAead);
        return new AeadProxy(_state, descriptor, _tracker);
    }

    public IKdfService GetKdf(AlgorithmId algorithmId)
    {
        ThrowIfDisposed();
        AlgorithmDescriptor descriptor = Resolve(algorithmId, AlgorithmCategory.KeyDerivation);
        return new KdfProxy(_state, descriptor, _tracker);
    }

    public void Destroy(PrivateKeyHandle handle)
    {
        ThrowIfDisposed();
        ValidateHandleProvider(ProviderId, handle.ProviderId, "PrivateKeyHandle", "Destroy");
        _tracker.ValidateOwnership(handle, "Destroy");

        lock (_state.OperationSyncRoot)
        {
            _state.ThrowIfStopping();

            var req = new DestroyHandleRequest(
                _state.NewRequestHeader(OopMessageType.DestroyHandleRequest),
                DestroyHandleKind.PrivateKey,
                handle.ProviderId,
                handle.Value);

            _state.Connection.DestroyHandleAsync(req, CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
        }

        _tracker.Untrack(handle);
    }

    public void Destroy(SecretKeyHandle handle)
    {
        ThrowIfDisposed();
        ValidateHandleProvider(ProviderId, handle.ProviderId, "SecretKeyHandle", "Destroy");
        _tracker.ValidateOwnership(handle, "Destroy");

        lock (_state.OperationSyncRoot)
        {
            _state.ThrowIfStopping();

            var req = new DestroyHandleRequest(
                _state.NewRequestHeader(OopMessageType.DestroyHandleRequest),
                DestroyHandleKind.SecretKey,
                handle.ProviderId,
                handle.Value);

            _state.Connection.DestroyHandleAsync(req, CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
        }

        _tracker.Untrack(handle);
    }

    public void Destroy(SharedSecretHandle handle)
    {
        ThrowIfDisposed();
        ValidateHandleProvider(ProviderId, handle.ProviderId, "SharedSecretHandle", "Destroy");
        _tracker.ValidateOwnership(handle, "Destroy");

        lock (_state.OperationSyncRoot)
        {
            _state.ThrowIfStopping();

            var req = new DestroyHandleRequest(
                _state.NewRequestHeader(OopMessageType.DestroyHandleRequest),
                DestroyHandleKind.SharedSecret,
                handle.ProviderId,
                handle.Value);

            _state.Connection.DestroyHandleAsync(req, CancellationToken.None)
                .AsTask().GetAwaiter().GetResult();
        }

        _tracker.Untrack(handle);
    }

    /// <summary>
    /// F3-FIX: Dispose drains the session handle tracker and performs best-effort
    /// destruction of any handles that were not explicitly destroyed by the caller.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;

        var remaining = _tracker.DrainAll();
        DestroyRemainingHandlesBestEffort(remaining);
    }

    private void DestroyRemainingHandlesBestEffort(SessionHandleTracker.TrackedHandles remaining)
    {
        foreach (var guid in remaining.PrivateKeys)
            TryDestroyHandle(DestroyHandleKind.PrivateKey, guid);

        foreach (var guid in remaining.SecretKeys)
            TryDestroyHandle(DestroyHandleKind.SecretKey, guid);

        foreach (var guid in remaining.SharedSecrets)
            TryDestroyHandle(DestroyHandleKind.SharedSecret, guid);
    }

    private void TryDestroyHandle(DestroyHandleKind kind, Guid handleValue)
    {
        try
        {
            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var req = new DestroyHandleRequest(
                    _state.NewRequestHeader(OopMessageType.DestroyHandleRequest),
                    kind,
                    ProviderId,
                    handleValue);

                _state.Connection.DestroyHandleAsync(req, CancellationToken.None)
                    .AsTask().GetAwaiter().GetResult();
            }
        }
        catch
        {
            // Best-effort: provider may be stopping or connection may be broken.
        }
    }

    private AlgorithmDescriptor Resolve(AlgorithmId algorithmId, AlgorithmCategory expectedCategory)
    {
        var caps = _record.Capabilities.Algorithms;
        for (int i = 0; i < caps.Length; i++)
        {
            var d = caps[i];
            if (d.Id.Equals(algorithmId) && d.Category == expectedCategory)
            {
                if (_effectiveCompliance is not null && _complianceGate is not null)
                {
                    ComplianceDecision decision = _complianceGate.Evaluate(d, _record.Metadata, _effectiveCompliance);
                    if (!decision.IsAllowed)
                    {
                        throw new InvalidOperationException(
                            $"Compliance gate rejected algorithm '{algorithmId.Value}' on provider '{ProviderId.Value}': {decision.Reason}");
                    }
                }

                return d;
            }
        }

        throw new InvalidOperationException(
            $"Algorithm '{algorithmId.Value}' with category '{expectedCategory}' is not available on provider '{ProviderId.Value}'.");
    }

    private static bool BoundarySatisfies(RequiredBoundaryClass actual, RequiredBoundaryClass required)
        => (int)actual >= (int)required;

    /// <summary>
    /// F7-FIX: Asserts that the provider's compliance envelope permits raw secret egress.
    /// When <see cref="ProviderModel.ProviderComplianceEnvelope.SupportsRawSecretEgress"/> is
    /// <see langword="false"/>, no raw private key or secret key material may leave the provider
    /// boundary. This guard must be called before any operation that would expose raw secret bytes
    /// through the OOP transport or export path.
    /// </summary>
    /// <param name="operation">Human-readable operation name for the error message.</param>
    /// <exception cref="InvalidOperationException">Thrown when raw secret egress is not permitted.</exception>
    internal void AssertRawSecretEgressPermitted(string operation)
    {
        if (!_record.Metadata.ComplianceEnvelope.SupportsRawSecretEgress)
        {
            throw new InvalidOperationException(
                $"{operation}: Raw secret egress is not permitted by the provider compliance envelope " +
                $"(SupportsRawSecretEgress=false on provider '{ProviderId.Value}'). " +
                "Secret key material cannot leave the provider boundary in raw form.");
        }
    }

    private static void ValidateHandleProvider(
        ProviderId expectedProviderId,
        ProviderId actualProviderId,
        string handleKind,
        string operation)
    {
        if (!expectedProviderId.Equals(actualProviderId))
        {
            throw new InvalidOperationException(
                $"{operation} rejected {handleKind} due to provider mismatch. Handle is bound to provider '{actualProviderId.Value}' on session/provider '{expectedProviderId.Value}'.");
        }
    }

    private static void EnsureRequestPayloadWithinBudget(LiveProviderSessionState state, string operation, params int[] segments)
        => OopTransportBudgetGuard.EnsureRequestPayloadWithinBudget(state.TransportBudget, operation, segments);

    private static void EnsureResponsePayloadWithinBudget(LiveProviderSessionState state, string operation, params int[] segments)
        => OopTransportBudgetGuard.EnsureResponsePayloadWithinBudget(state.TransportBudget, operation, segments);

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(Interlocked.CompareExchange(ref _disposed, 0, 0) != 0, this);
    }

    private sealed class KemProxy : IKemService
    {
        private readonly LiveProviderSessionState _state;
        private readonly AlgorithmDescriptor _descriptor;
        private readonly SessionHandleTracker _tracker;
        private int _disposed;

        public KemProxy(LiveProviderSessionState state, AlgorithmDescriptor descriptor, SessionHandleTracker tracker)
        {
            _state = state;
            _descriptor = descriptor;
            _tracker = tracker;
        }

        public ProviderId ProviderId => _descriptor.Provider;
        public AlgorithmId AlgorithmId => _descriptor.Id;
        public AlgorithmCategory Category => _descriptor.Category;

        public int PublicKeySize =>
            _descriptor.Id.Value switch
            {
                "ECDH-P384-KEM" => 97,
                "ML-KEM-512" => 800,
                "ML-KEM-768" => 1184,
                "ML-KEM-1024" => 1568,
                _ => throw new NotSupportedException($"Unknown KEM public key size for '{_descriptor.Id.Value}'.")
            };

        public int CiphertextSize =>
            _descriptor.Id.Value switch
            {
                "ECDH-P384-KEM" => 97,
                "ML-KEM-512" => 768,
                "ML-KEM-768" => 1088,
                "ML-KEM-1024" => 1568,
                _ => throw new NotSupportedException($"Unknown KEM ciphertext size for '{_descriptor.Id.Value}'.")
            };

        public KemKeyPair GenerateKeyPair()
        {
            ThrowIfDisposed();

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.KemGenerateKeyPairAsync(
                    new KemGenerateKeyPairRequest(
                        _state.NewRequestHeader(OopMessageType.KemGenerateKeyPairRequest),
                        _descriptor.Id),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.ValidateHandleProvider(ProviderId, response.KeyPair.PrivateKey.ProviderId, "PrivateKeyHandle", "KEM generate key pair");
                _tracker.Track(response.KeyPair.PrivateKey);
                return response.KeyPair;
            }
        }

        public KemEncapsulationResult Encapsulate(in PublicKey recipientPublicKey)
        {
            ThrowIfDisposed();
            ProviderRpcSession.EnsureRequestPayloadWithinBudget(_state, "KEM encapsulate", recipientPublicKey.Bytes.Length);

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.KemEncapsulateAsync(
                    new KemEncapsulateRequest(
                        _state.NewRequestHeader(OopMessageType.KemEncapsulateRequest),
                        _descriptor.Id,
                        recipientPublicKey),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.EnsureResponsePayloadWithinBudget(_state, "KEM encapsulate", response.Result.Ciphertext.Length);
                ProviderRpcSession.ValidateHandleProvider(ProviderId, response.Result.SharedSecret.ProviderId, "SharedSecretHandle", "KEM encapsulate");
                _tracker.Track(response.Result.SharedSecret);
                return response.Result;
            }
        }

        public SharedSecretHandle Decapsulate(PrivateKeyHandle privateKey, ReadOnlySpan<byte> ciphertext)
        {
            ThrowIfDisposed();
            ProviderRpcSession.ValidateHandleProvider(ProviderId, privateKey.ProviderId, "PrivateKeyHandle", "KEM decapsulate");
            _tracker.ValidateOwnership(privateKey, "KEM decapsulate");
            ProviderRpcSession.EnsureRequestPayloadWithinBudget(_state, "KEM decapsulate", ciphertext.Length);

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.KemDecapsulateAsync(
                    new KemDecapsulateRequest(
                        _state.NewRequestHeader(OopMessageType.KemDecapsulateRequest),
                        _descriptor.Id,
                        privateKey,
                        ciphertext),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.ValidateHandleProvider(ProviderId, response.SharedSecret.ProviderId, "SharedSecretHandle", "KEM decapsulate");
                _tracker.Track(response.SharedSecret);
                return response.SharedSecret;
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _disposed, 1);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(Interlocked.CompareExchange(ref _disposed, 0, 0) != 0, this);
        }
    }

    private sealed class SignatureProxy : ISignatureService
    {
        private readonly LiveProviderSessionState _state;
        private readonly AlgorithmDescriptor _descriptor;
        private readonly SessionHandleTracker _tracker;
        private int _disposed;

        public SignatureProxy(LiveProviderSessionState state, AlgorithmDescriptor descriptor, SessionHandleTracker tracker)
        {
            _state = state;
            _descriptor = descriptor;
            _tracker = tracker;
        }

        public ProviderId ProviderId => _descriptor.Provider;
        public AlgorithmId AlgorithmId => _descriptor.Id;
        public AlgorithmCategory Category => _descriptor.Category;

        public int PublicKeySize =>
            _descriptor.Id.Value switch
            {
                "ECDSA-P384" => 97,
                "ML-DSA-44" => 1312,
                "ML-DSA-65" => 1952,
                "ML-DSA-87" => 2592,
                _ => throw new NotSupportedException($"Unknown public key size for '{_descriptor.Id.Value}'.")
            };

        public int SignatureSize =>
            _descriptor.Id.Value switch
            {
                "ECDSA-P384" => 96,
                "ML-DSA-44" => 2420,
                "ML-DSA-65" => 3309,
                "ML-DSA-87" => 4627,
                _ => throw new NotSupportedException($"Unknown signature size for '{_descriptor.Id.Value}'.")
            };

        public SignatureKeyPair GenerateKeyPair()
        {
            ThrowIfDisposed();

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.SignatureGenerateKeyPairAsync(
                    new SignatureGenerateKeyPairRequest(
                        _state.NewRequestHeader(OopMessageType.SignatureGenerateKeyPairRequest),
                        _descriptor.Id),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.ValidateHandleProvider(ProviderId, response.KeyPair.PrivateKey.ProviderId, "PrivateKeyHandle", "Signature generate key pair");
                _tracker.Track(response.KeyPair.PrivateKey);
                return response.KeyPair;
            }
        }

        public void Sign(PrivateKeyHandle privateKey, ReadOnlySpan<byte> message, Span<byte> signatureOut)
        {
            ThrowIfDisposed();
            ProviderRpcSession.ValidateHandleProvider(ProviderId, privateKey.ProviderId, "PrivateKeyHandle", "Signature sign");
            _tracker.ValidateOwnership(privateKey, "Signature sign");
            ProviderRpcSession.EnsureRequestPayloadWithinBudget(_state, "Signature sign", message.Length);

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.SignatureSignAsync(
                    new SignatureSignRequest(
                        _state.NewRequestHeader(OopMessageType.SignatureSignRequest),
                        _descriptor.Id,
                        privateKey,
                        message),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.EnsureResponsePayloadWithinBudget(_state, "Signature sign", response.Signature.Length);

                if (response.Signature.Length > signatureOut.Length)
                    throw new InvalidOperationException("Provided signatureOut buffer is too small.");

                response.Signature.Span.CopyTo(signatureOut);
            }
        }

        public bool Verify(in PublicKey publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            ThrowIfDisposed();
            ProviderRpcSession.EnsureRequestPayloadWithinBudget(_state, "Signature verify", publicKey.Bytes.Length, message.Length, signature.Length);

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.SignatureVerifyAsync(
                    new SignatureVerifyRequest(
                        _state.NewRequestHeader(OopMessageType.SignatureVerifyRequest),
                        _descriptor.Id,
                        publicKey,
                        message,
                        signature),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                return response.IsValid;
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _disposed, 1);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(Interlocked.CompareExchange(ref _disposed, 0, 0) != 0, this);
        }
    }

    private sealed class AeadProxy : IAeadService
    {
        private readonly LiveProviderSessionState _state;
        private readonly AlgorithmDescriptor _descriptor;
        private readonly SessionHandleTracker _tracker;
        private int _disposed;

        public AeadProxy(LiveProviderSessionState state, AlgorithmDescriptor descriptor, SessionHandleTracker tracker)
        {
            _state = state;
            _descriptor = descriptor;
            _tracker = tracker;
        }

        public ProviderId ProviderId => _descriptor.Provider;
        public AlgorithmId AlgorithmId => _descriptor.Id;
        public AlgorithmCategory Category => _descriptor.Category;

        public int KeySize =>
            _descriptor.Id.Value switch
            {
                "AES-256-GCM" => 32,
                _ => throw new NotSupportedException($"Unknown AEAD key size for '{_descriptor.Id.Value}'.")
            };

        public int NonceSize =>
            _descriptor.Id.Value switch
            {
                "AES-256-GCM" => 12,
                _ => throw new NotSupportedException($"Unknown AEAD nonce size for '{_descriptor.Id.Value}'.")
            };

        public int TagSize =>
            _descriptor.Id.Value switch
            {
                "AES-256-GCM" => 16,
                _ => throw new NotSupportedException($"Unknown AEAD tag size for '{_descriptor.Id.Value}'.")
            };

        public SecretKeyHandle GenerateKey()
        {
            ThrowIfDisposed();

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.AeadGenerateKeyAsync(
                    new AeadGenerateKeyRequest(
                        _state.NewRequestHeader(OopMessageType.AeadGenerateKeyRequest),
                        _descriptor.Id),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.ValidateHandleProvider(ProviderId, response.KeyHandle.ProviderId, "SecretKeyHandle", "AEAD generate key");
                _tracker.Track(response.KeyHandle);
                return response.KeyHandle;
            }
        }

        public int GetCiphertextSize(int plaintextSize) => checked(plaintextSize + TagSize);

        public int GetPlaintextSize(int ciphertextSize)
        {
            int pt = ciphertextSize - TagSize;
            if (pt < 0)
                throw new ArgumentOutOfRangeException(nameof(ciphertextSize));
            return pt;
        }

        public void Encrypt(
            SecretKeyHandle key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            Span<byte> ciphertextOut)
        {
            ThrowIfDisposed();
            ProviderRpcSession.ValidateHandleProvider(ProviderId, key.ProviderId, "SecretKeyHandle", "AEAD encrypt");
            _tracker.ValidateOwnership(key, "AEAD encrypt");
            ProviderRpcSession.EnsureRequestPayloadWithinBudget(_state, "AEAD encrypt", nonce.Length, plaintext.Length, associatedData.Length);

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                // F5-FIX: Dispose request (zeroizes plaintext copy) and response (zeroizes ciphertext copy).
                using var request = new AeadEncryptRequest(
                    _state.NewRequestHeader(OopMessageType.AeadEncryptRequest),
                    _descriptor.Id,
                    key,
                    nonce,
                    plaintext,
                    associatedData);

                using var response = _state.Connection.AeadEncryptAsync(
                    request,
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.EnsureResponsePayloadWithinBudget(_state, "AEAD encrypt", response.Ciphertext.Length);

                if (response.Ciphertext.Length > ciphertextOut.Length)
                    throw new InvalidOperationException("Provided ciphertextOut buffer is too small.");

                response.Ciphertext.Span.CopyTo(ciphertextOut);
            }
        }

        public bool Decrypt(
            SecretKeyHandle key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> associatedData,
            Span<byte> plaintextOut)
        {
            ThrowIfDisposed();
            ProviderRpcSession.ValidateHandleProvider(ProviderId, key.ProviderId, "SecretKeyHandle", "AEAD decrypt");
            _tracker.ValidateOwnership(key, "AEAD decrypt");
            ProviderRpcSession.EnsureRequestPayloadWithinBudget(_state, "AEAD decrypt", nonce.Length, ciphertext.Length, associatedData.Length);

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                // F5-FIX: Dispose request (zeroizes ciphertext copy) and response (zeroizes plaintext copy).
                using var request = new AeadDecryptRequest(
                    _state.NewRequestHeader(OopMessageType.AeadDecryptRequest),
                    _descriptor.Id,
                    key,
                    nonce,
                    ciphertext,
                    associatedData);

                using var response = _state.Connection.AeadDecryptAsync(
                    request,
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                if (!response.IsValid)
                    return false;

                ProviderRpcSession.EnsureResponsePayloadWithinBudget(_state, "AEAD decrypt", response.Plaintext.Length);

                if (response.Plaintext.Length > plaintextOut.Length)
                    throw new InvalidOperationException("Provided plaintextOut buffer is too small.");

                response.Plaintext.Span.CopyTo(plaintextOut);
                return true;
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _disposed, 1);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(Interlocked.CompareExchange(ref _disposed, 0, 0) != 0, this);
        }
    }

    private sealed class KdfProxy : IKdfService
    {
        private readonly LiveProviderSessionState _state;
        private readonly AlgorithmDescriptor _descriptor;
        private readonly SessionHandleTracker _tracker;
        private int _disposed;

        public KdfProxy(LiveProviderSessionState state, AlgorithmDescriptor descriptor, SessionHandleTracker tracker)
        {
            _state = state;
            _descriptor = descriptor;
            _tracker = tracker;
        }

        public ProviderId ProviderId => _descriptor.Provider;
        public AlgorithmId AlgorithmId => _descriptor.Id;
        public AlgorithmCategory Category => _descriptor.Category;

        public SecretKeyHandle DeriveKey(SharedSecretHandle sharedSecret, in KdfParameters parameters)
        {
            ThrowIfDisposed();
            ProviderRpcSession.ValidateHandleProvider(ProviderId, sharedSecret.ProviderId, "SharedSecretHandle", "KDF derive key");
            _tracker.ValidateOwnership(sharedSecret, "KDF derive key");

            int derivedKeyBytes = parameters.OutputKeyBits > 0 && parameters.OutputKeyBits % 8 == 0
                ? checked(parameters.OutputKeyBits / 8)
                : 0;

            ProviderRpcSession.EnsureRequestPayloadWithinBudget(_state, "KDF derive key", parameters.Salt.Length, parameters.Info.Length, derivedKeyBytes);

            lock (_state.OperationSyncRoot)
            {
                _state.ThrowIfStopping();

                var response = _state.Connection.KdfDeriveKeyAsync(
                    new KdfDeriveKeyRequest(
                        _state.NewRequestHeader(OopMessageType.KdfDeriveKeyRequest),
                        _descriptor.Id,
                        sharedSecret,
                        parameters),
                    CancellationToken.None).AsTask().GetAwaiter().GetResult();

                ProviderRpcSession.ValidateHandleProvider(ProviderId, response.SecretKeyHandle.ProviderId, "SecretKeyHandle", "KDF derive key");
                _tracker.Track(response.SecretKeyHandle);
                return response.SecretKeyHandle;
            }
        }

        public void Dispose()
        {
            Interlocked.Exchange(ref _disposed, 1);
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(Interlocked.CompareExchange(ref _disposed, 0, 0) != 0, this);
        }
    }
}

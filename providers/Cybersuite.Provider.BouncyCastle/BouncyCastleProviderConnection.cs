using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.OopProtocol.Session;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Trust;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Concrete in-process provider connection that emulates the OOP contract surface for Bouncy Castle.
/// Implements operation-level RPCs for a stable classical subset plus experimental ML-KEM / ML-DSA.
/// </summary>
public sealed class BouncyCastleProviderConnection : IProviderConnection
{
    private readonly ProviderPackage _package;
    private readonly ProviderIdentity _identity;
    private readonly CapabilitySnapshot _capabilities;
    private readonly byte[] _capabilityCanonicalBytes;
    private readonly HashSet<string> _advertisedAlgorithms = new(StringComparer.Ordinal);
    private readonly SecureRandom _random = new();
    private readonly BouncyCastleKeyMaterialStore _store = new();

    private readonly object _gate = new();

    private OopSessionBinding? _sessionBinding;
    private ulong _lastAcceptedCounter;
    private bool _shutdown;
    private bool _disposed;

    public BouncyCastleProviderConnection(ProviderPackage package)
    {
        ArgumentNullException.ThrowIfNull(package);

        _package = package;

        string buildHash = package.Manifest.EntrypointSha256Hex ?? "UNSPECIFIED";
        _identity = new ProviderIdentity(
            providerId: package.Manifest.ProviderId,
            version: package.Manifest.Version,
            buildHash: buildHash,
            signatureFingerprint: null);

        bool includeExperimentalAlgorithms = package.Manifest.IsExperimental;
        _capabilities = BouncyCastleCapabilityCatalog.CreateSnapshot(_identity, includeExperimentalAlgorithms);
        _capabilityCanonicalBytes = _capabilities.GetCanonicalBytes();

        for (int i = 0; i < _capabilities.Algorithms.Length; i++)
            _advertisedAlgorithms.Add(_capabilities.Algorithms[i].Id.Value);
    }

    public ValueTask<ProviderHello> HandshakeAsync(ClientHello clientHello, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();

            byte[] nonce = new byte[OopConstants.NonceSizeBytes];
            _random.NextBytes(nonce);

            byte[]? attestationEvidence = CreateAttestationEvidenceOrNull();
            try
            {
                var hello = new ProviderHello(
                    version: ProtocolVersion.V1_0,
                    nonce32: nonce,
                    identity: _identity,
                    capabilityHashSha384: _capabilities.CapabilityHashSha384.Span,
                    complianceEnvelope: _package.Manifest.ComplianceEnvelope,
                    isExperimental: _package.Manifest.IsExperimental,
                    attestationEvidence: attestationEvidence);

                _sessionBinding = OopSessionBinding.Create(clientHello, hello);
                _lastAcceptedCounter = 0;

                return ValueTask.FromResult(hello);
            }
            finally
            {
                if (attestationEvidence is not null)
                    CryptographicOperations.ZeroMemory(attestationEvidence);
            }
        }
    }

    public ValueTask<CapabilityResponse> GetCapabilitiesAsync(CapabilityRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        OopResponseHeader header;
        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.CapabilityRequest);

            header = new OopResponseHeader(
                version: request.Header.Version,
                messageType: OopMessageType.CapabilityResponse,
                requestId: request.Header.RequestId,
                messageCounter: request.Header.MessageCounter,
                channelBindingSha384: request.Header.ChannelBindingSha384.Span,
                success: true,
                error: null);
        }

        return ValueTask.FromResult(
            new CapabilityResponse(
                header,
                _capabilityCanonicalBytes,
                _capabilities.CapabilityHashSha384.Span));
    }

    public ValueTask<HealthResponse> HealthAsync(HealthRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        OopResponseHeader header;
        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.HealthRequest);

            header = new OopResponseHeader(
                version: request.Header.Version,
                messageType: OopMessageType.HealthResponse,
                requestId: request.Header.RequestId,
                messageCounter: request.Header.MessageCounter,
                channelBindingSha384: request.Header.ChannelBindingSha384.Span,
                success: true,
                error: null);
        }

        return ValueTask.FromResult(new HealthResponse(header, isHealthy: true));
    }

    public ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        OopResponseHeader header;
        lock (_gate)
        {
            ThrowIfDisposed();
            ValidateRequestHeader(request.Header, OopMessageType.ShutdownRequest);

            _shutdown = true;

            header = new OopResponseHeader(
                version: request.Header.Version,
                messageType: OopMessageType.ShutdownResponse,
                requestId: request.Header.RequestId,
                messageCounter: request.Header.MessageCounter,
                channelBindingSha384: request.Header.ChannelBindingSha384.Span,
                success: true,
                error: null);
        }

        return ValueTask.FromResult(new ShutdownResponse(header));
    }

    public ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        KemKeyPair result;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.KemGenerateKeyPairRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "KEM generate key pair");

            if (IsMlKemAlgorithm(request.AlgorithmId))
            {
                result = BouncyCastleMlReflection.GenerateMlKemKeyPair(
                    _identity.ProviderId,
                    request.AlgorithmId,
                    new AlgorithmParameterSetId(request.AlgorithmId.Value),
                    _store,
                    _random);
            }
            else
            {
                RequireAlgorithm(request.AlgorithmId, "ECDH-P384-KEM");

                var keyPair = BouncyCastleCurveP384.GenerateKeyPair(_random);
                var publicKey = BouncyCastleCurveP384.ToPublicKey(
                    request.AlgorithmId,
                    (ECPublicKeyParameters)keyPair.Public);

                var privateHandle = _store.AddPrivateKey(
                    _identity.ProviderId,
                    (ECPrivateKeyParameters)keyPair.Private);

                result = new KemKeyPair(publicKey, privateHandle);
            }

            header = SuccessHeader(request.Header, OopMessageType.KemGenerateKeyPairResponse);
        }

        return ValueTask.FromResult(new KemGenerateKeyPairResponse(header, result));
    }

    public ValueTask<KemEncapsulateResponse> KemEncapsulateAsync(KemEncapsulateRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        KemEncapsulationResult result;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.KemEncapsulateRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "KEM encapsulate");

            if (IsMlKemAlgorithm(request.AlgorithmId))
            {
                result = BouncyCastleMlReflection.EncapsulateMlKem(
                    _identity.ProviderId,
                    request.AlgorithmId,
                    new AlgorithmParameterSetId(request.AlgorithmId.Value),
                    request.RecipientPublicKey,
                    _store,
                    _random);
            }
            else
            {
                RequireAlgorithm(request.AlgorithmId, "ECDH-P384-KEM");

                var recipientPk = BouncyCastleCurveP384.ParsePublicKey(request.RecipientPublicKey.Bytes.Span);
                var ephemeral = BouncyCastleCurveP384.GenerateKeyPair(_random);

                byte[] sharedSecret = BouncyCastleCurveP384.DeriveSharedSecret(
                    (ECPrivateKeyParameters)ephemeral.Private,
                    recipientPk);

                var sharedHandle = _store.AddSharedSecret(_identity.ProviderId, sharedSecret);
                CryptographicOperations.ZeroMemory(sharedSecret);

                byte[] ciphertext = ((ECPublicKeyParameters)ephemeral.Public).Q.GetEncoded(false);
                result = new KemEncapsulationResult(ciphertext, sharedHandle);
            }

            header = SuccessHeader(request.Header, OopMessageType.KemEncapsulateResponse);
        }

        return ValueTask.FromResult(new KemEncapsulateResponse(header, result));
    }

    public ValueTask<KemDecapsulateResponse> KemDecapsulateAsync(KemDecapsulateRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        SharedSecretHandle handle;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.KemDecapsulateRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "KEM decapsulate");

            EnsurePrivateKeyHandleProvider(request.PrivateKey, "KEM decapsulate");

            if (IsMlKemAlgorithm(request.AlgorithmId))
            {
                handle = BouncyCastleMlReflection.DecapsulateMlKem(
                    _identity.ProviderId,
                    new AlgorithmParameterSetId(request.AlgorithmId.Value),
                    request.PrivateKey,
                    request.Ciphertext.Span,
                    _store);
            }
            else
            {
                RequireAlgorithm(request.AlgorithmId, "ECDH-P384-KEM");

                var privateKey = _store.GetEcPrivateKey(request.PrivateKey);
                var ephemeralPublic = BouncyCastleCurveP384.ParsePublicKey(request.Ciphertext.Span);

                byte[] sharedSecret = BouncyCastleCurveP384.DeriveSharedSecret(privateKey, ephemeralPublic);
                handle = _store.AddSharedSecret(_identity.ProviderId, sharedSecret);
                CryptographicOperations.ZeroMemory(sharedSecret);
            }

            header = SuccessHeader(request.Header, OopMessageType.KemDecapsulateResponse);
        }

        return ValueTask.FromResult(new KemDecapsulateResponse(header, handle));
    }

    public ValueTask<SignatureGenerateKeyPairResponse> SignatureGenerateKeyPairAsync(SignatureGenerateKeyPairRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        SignatureKeyPair result;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.SignatureGenerateKeyPairRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "Signature generate key pair");

            if (IsMlDsaAlgorithm(request.AlgorithmId))
            {
                result = BouncyCastleMlReflection.GenerateMlDsaKeyPair(
                    _identity.ProviderId,
                    request.AlgorithmId,
                    new AlgorithmParameterSetId(request.AlgorithmId.Value),
                    _store,
                    _random);
            }
            else
            {
                RequireAlgorithm(request.AlgorithmId, "ECDSA-P384");

                var keyPair = BouncyCastleCurveP384.GenerateKeyPair(_random);
                var publicKey = BouncyCastleCurveP384.ToPublicKey(
                    request.AlgorithmId,
                    (ECPublicKeyParameters)keyPair.Public);

                var privateHandle = _store.AddPrivateKey(
                    _identity.ProviderId,
                    (ECPrivateKeyParameters)keyPair.Private);

                result = new SignatureKeyPair(publicKey, privateHandle);
            }

            header = SuccessHeader(request.Header, OopMessageType.SignatureGenerateKeyPairResponse);
        }

        return ValueTask.FromResult(new SignatureGenerateKeyPairResponse(header, result));
    }

    public ValueTask<SignatureSignResponse> SignatureSignAsync(SignatureSignRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] signature;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.SignatureSignRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "Signature sign");

            EnsurePrivateKeyHandleProvider(request.PrivateKey, "Signature sign");

            if (IsMlDsaAlgorithm(request.AlgorithmId))
            {
                signature = BouncyCastleMlReflection.SignMlDsa(
                    new AlgorithmParameterSetId(request.AlgorithmId.Value),
                    request.PrivateKey,
                    request.Message.Span,
                    _store);
            }
            else
            {
                RequireAlgorithm(request.AlgorithmId, "ECDSA-P384");

                var privateKey = _store.GetEcPrivateKey(request.PrivateKey);
                byte[] digest = ComputeSha384(request.Message.Span);

                try
                {
                    var signer = new ECDsaSigner();
                    signer.Init(true, privateKey);
                    BigInteger[] rs = signer.GenerateSignature(digest);

                    signature = EncodeP384Signature(rs[0], rs[1]);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(digest);
                }
            }

            header = SuccessHeader(request.Header, OopMessageType.SignatureSignResponse);
        }

        return ValueTask.FromResult(new SignatureSignResponse(header, signature));
    }

    public ValueTask<SignatureVerifyResponse> SignatureVerifyAsync(SignatureVerifyRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        bool isValid;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.SignatureVerifyRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "Signature verify");

            if (IsMlDsaAlgorithm(request.AlgorithmId))
            {
                isValid = BouncyCastleMlReflection.VerifyMlDsa(
                    new AlgorithmParameterSetId(request.AlgorithmId.Value),
                    request.PublicKey,
                    request.Message.Span,
                    request.Signature.Span);
            }
            else
            {
                RequireAlgorithm(request.AlgorithmId, "ECDSA-P384");

                var publicKey = BouncyCastleCurveP384.ParsePublicKey(request.PublicKey.Bytes.Span);
                byte[] digest = ComputeSha384(request.Message.Span);

                try
                {
                    DecodeP384Signature(request.Signature.Span, out var r, out var s);

                    var verifier = new ECDsaSigner();
                    verifier.Init(false, publicKey);
                    isValid = verifier.VerifySignature(digest, r, s);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(digest);
                }
            }

            header = SuccessHeader(request.Header, OopMessageType.SignatureVerifyResponse);
        }

        return ValueTask.FromResult(new SignatureVerifyResponse(header, isValid));
    }

    public ValueTask<AeadGenerateKeyResponse> AeadGenerateKeyAsync(AeadGenerateKeyRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        SecretKeyHandle handle;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.AeadGenerateKeyRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "AEAD generate key");

            RequireAlgorithm(request.AlgorithmId, "AES-256-GCM");

            byte[] key = new byte[32];
            RandomNumberGenerator.Fill(key);

            handle = _store.AddSecretKey(_identity.ProviderId, key);
            CryptographicOperations.ZeroMemory(key);

            header = SuccessHeader(request.Header, OopMessageType.AeadGenerateKeyResponse);
        }

        return ValueTask.FromResult(new AeadGenerateKeyResponse(header, handle));
    }

    public ValueTask<AeadEncryptResponse> AeadEncryptAsync(AeadEncryptRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        byte[] ciphertext;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.AeadEncryptRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "AEAD encrypt");

            RequireAlgorithm(request.AlgorithmId, "AES-256-GCM");
            EnsureSecretKeyHandleProvider(request.KeyHandle, "AEAD encrypt");

            if (request.Nonce.Length != 12)
                throw new OopProtocolException("AES-256-GCM requires a 12-byte nonce.");

            // F5-FIX: Use pooled lease instead of bare ToArray() for secret key material.
            using var keyLease = _store.LeaseSecretKey(request.KeyHandle);
            // F5-FIX: Use pooled lease for plaintext copy passed to BouncyCastle.
            using var plaintextLease = SensitiveBufferLease.CopyFrom(request.Plaintext.Span);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(keyLease.DangerousGetArray(), 0, keyLease.Length),
                128,
                request.Nonce.ToArray(),
                request.AssociatedData.ToArray());

            cipher.Init(true, parameters);

            ciphertext = new byte[cipher.GetOutputSize(request.Plaintext.Length)];
            int len = cipher.ProcessBytes(
                plaintextLease.DangerousGetArray(),
                0,
                plaintextLease.Length,
                ciphertext,
                0);

            len += cipher.DoFinal(ciphertext, len);

            if (len != ciphertext.Length)
            {
                byte[] exact = new byte[len];
                Array.Copy(ciphertext, exact, len);
                CryptographicOperations.ZeroMemory(ciphertext);
                ciphertext = exact;
            }

            header = SuccessHeader(request.Header, OopMessageType.AeadEncryptResponse);
        }

        return ValueTask.FromResult(new AeadEncryptResponse(header, ciphertext));
    }

    public ValueTask<AeadDecryptResponse> AeadDecryptAsync(AeadDecryptRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        bool isValid;
        byte[] plaintext = Array.Empty<byte>();
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.AeadDecryptRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "AEAD decrypt");

            RequireAlgorithm(request.AlgorithmId, "AES-256-GCM");
            EnsureSecretKeyHandleProvider(request.KeyHandle, "AEAD decrypt");

            if (request.Nonce.Length != 12)
                throw new OopProtocolException("AES-256-GCM requires a 12-byte nonce.");

            // F5-FIX: Use pooled lease instead of bare ToArray() for secret key material.
            using var keyLease = _store.LeaseSecretKey(request.KeyHandle);
            // F5-FIX: Use pooled lease for ciphertext copy passed to BouncyCastle.
            using var ciphertextLease = SensitiveBufferLease.CopyFrom(request.Ciphertext.Span);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(
                new KeyParameter(keyLease.DangerousGetArray(), 0, keyLease.Length),
                128,
                request.Nonce.ToArray(),
                request.AssociatedData.ToArray());

            cipher.Init(false, parameters);

            byte[] candidate = new byte[cipher.GetOutputSize(request.Ciphertext.Length)];
            try
            {
                int len = cipher.ProcessBytes(
                    ciphertextLease.DangerousGetArray(),
                    0,
                    ciphertextLease.Length,
                    candidate,
                    0);

                len += cipher.DoFinal(candidate, len);

                if (len != candidate.Length)
                {
                    plaintext = new byte[len];
                    Array.Copy(candidate, plaintext, len);
                    CryptographicOperations.ZeroMemory(candidate);
                }
                else
                {
                    plaintext = candidate;
                }

                isValid = true;
            }
            catch
            {
                CryptographicOperations.ZeroMemory(candidate);
                plaintext = Array.Empty<byte>();
                isValid = false;
            }

            header = SuccessHeader(request.Header, OopMessageType.AeadDecryptResponse);
        }

        return ValueTask.FromResult(new AeadDecryptResponse(header, isValid, plaintext));
    }

    public ValueTask<KdfDeriveKeyResponse> KdfDeriveKeyAsync(KdfDeriveKeyRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        SecretKeyHandle handle;
        OopResponseHeader header;

        lock (_gate)
        {
            ThrowIfDisposedOrShutdown();
            ValidateRequestHeader(request.Header, OopMessageType.KdfDeriveKeyRequest);
            RequireAdvertisedAlgorithm(request.AlgorithmId, "KDF derive key");

            RequireAlgorithm(request.AlgorithmId, "HKDF-SHA384");
            EnsureSharedSecretHandleProvider(request.SharedSecretHandle, "KDF derive key");

            if (request.Parameters.OutputKeyBits <= 0 || request.Parameters.OutputKeyBits % 8 != 0)
                throw new OopProtocolException("OutputKeyBits must be positive and divisible by 8.");

            // F5-FIX: Use pooled lease instead of bare ToArray() for IKM (shared secret).
            // The lease auto-zeroizes the pooled copy; we still need an exact-length array
            // for HkdfParameters (no offset/length overload), which is manually zeroized.
            using var ikmLease = _store.LeaseSharedSecret(request.SharedSecretHandle);
            byte[] ikmExact = ikmLease.ReadOnlySpan.ToArray();

            int outLen = checked(request.Parameters.OutputKeyBits / 8);
            using var outputLease = SensitiveBufferLease.Rent(outLen);

            try
            {
                var hkdf = new Org.BouncyCastle.Crypto.Generators.HkdfBytesGenerator(new Sha384Digest());
                hkdf.Init(new Org.BouncyCastle.Crypto.Parameters.HkdfParameters(
                    ikmExact,
                    request.Parameters.Salt.ToArray(),
                    request.Parameters.Info.ToArray()));

                hkdf.GenerateBytes(outputLease.DangerousGetArray(), 0, outputLease.Length);

                handle = _store.AddSecretKey(_identity.ProviderId, outputLease.ReadOnlySpan);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ikmExact);
            }

            header = SuccessHeader(request.Header, OopMessageType.KdfDeriveKeyResponse);
        }

        return ValueTask.FromResult(new KdfDeriveKeyResponse(header, handle));
    }

    public ValueTask<DestroyHandleResponse> DestroyHandleAsync(DestroyHandleRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        OopResponseHeader header;
        lock (_gate)
        {
            ThrowIfDisposed();

            ValidateRequestHeader(request.Header, OopMessageType.DestroyHandleRequest);

            if (!_identity.ProviderId.Equals(request.ProviderId))
                throw new OopProtocolException("DestroyHandle request provider mismatch.");

            switch (request.Kind)
            {
                case DestroyHandleKind.PrivateKey:
                    _store.Destroy(new PrivateKeyHandle(request.ProviderId, request.HandleValue));
                    break;
                case DestroyHandleKind.SecretKey:
                    _store.Destroy(new SecretKeyHandle(request.ProviderId, request.HandleValue));
                    break;
                case DestroyHandleKind.SharedSecret:
                    _store.Destroy(new SharedSecretHandle(request.ProviderId, request.HandleValue));
                    break;
                default:
                    throw new OopProtocolException("Unknown DestroyHandleKind.");
            }

            header = SuccessHeader(request.Header, OopMessageType.DestroyHandleResponse);
        }

        return ValueTask.FromResult(new DestroyHandleResponse(header));
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposed)
                return ValueTask.CompletedTask;

            _disposed = true;
            _shutdown = true;
            _sessionBinding = null;

            CryptographicOperations.ZeroMemory(_capabilityCanonicalBytes);
            _store.Dispose();

            return ValueTask.CompletedTask;
        }
    }

    private static OopResponseHeader SuccessHeader(OopRequestHeader requestHeader, OopMessageType responseType)
        => new(
            version: requestHeader.Version,
            messageType: responseType,
            requestId: requestHeader.RequestId,
            messageCounter: requestHeader.MessageCounter,
            channelBindingSha384: requestHeader.ChannelBindingSha384.Span,
            success: true,
            error: null);

    private void ValidateRequestHeader(OopRequestHeader header, OopMessageType expectedMessageType)
    {
        if (header.MessageType != expectedMessageType)
            throw new OopProtocolException($"Unexpected message type. Expected {expectedMessageType}, got {header.MessageType}.");

        if (_sessionBinding is null)
            throw new OopProtocolException("Provider session is not bound. Handshake required.");

        if (!_sessionBinding.ValidateChannelBinding(header.ChannelBindingSha384.Span))
            throw new OopProtocolException("Channel binding mismatch.");

        if (header.MessageCounter <= _lastAcceptedCounter)
            throw new OopProtocolException("Replay or out-of-order message counter detected.");

        _lastAcceptedCounter = header.MessageCounter;
    }

    private static byte[] ComputeSha384(ReadOnlySpan<byte> message)
    {
        var digest = new Sha384Digest();
        // F5-FIX: Use pooled lease instead of bare ToArray() for the message copy.
        using var msgLease = SensitiveBufferLease.CopyFrom(message);
        digest.BlockUpdate(msgLease.DangerousGetArray(), 0, msgLease.Length);
        byte[] output = new byte[digest.GetDigestSize()];
        digest.DoFinal(output, 0);
        return output;
    }

    private static byte[] EncodeP384Signature(BigInteger r, BigInteger s)
    {
        byte[] rb = Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(48, r);
        byte[] sb = Org.BouncyCastle.Utilities.BigIntegers.AsUnsignedByteArray(48, s);

        byte[] sig = new byte[96];
        Buffer.BlockCopy(rb, 0, sig, 0, 48);
        Buffer.BlockCopy(sb, 0, sig, 48, 48);

        CryptographicOperations.ZeroMemory(rb);
        CryptographicOperations.ZeroMemory(sb);

        return sig;
    }

    private static void DecodeP384Signature(ReadOnlySpan<byte> signature, out BigInteger r, out BigInteger s)
    {
        if (signature.Length != 96)
            throw new OopProtocolException("ECDSA-P384 signature must be exactly 96 bytes (r||s).");

        r = new BigInteger(1, signature[..48].ToArray());
        s = new BigInteger(1, signature[48..].ToArray());
    }

    private static void RequireAlgorithm(AlgorithmId actual, string expected)
    {
        if (!string.Equals(actual.Value, expected, StringComparison.Ordinal))
            throw new OopProtocolException($"Algorithm '{actual.Value}' not supported by this provider connection (expected '{expected}').");
    }

    private byte[]? CreateAttestationEvidenceOrNull()
    {
        if (_package.Manifest.ComplianceEnvelope.AttestationMode == AttestationMode.None)
            return null;

        var statement = new ProviderStructuredAttestationStatement(
            ProviderId: _identity.ProviderId.Value,
            BuildHashSha256Hex: _identity.BuildHash,
            SecurityClass: _package.Manifest.ComplianceEnvelope.SecurityClass,
            BoundaryClass: _package.Manifest.ComplianceEnvelope.BoundaryClass,
            ModuleName: _package.Manifest.ComplianceEnvelope.DeclaredModuleName,
            ModuleVersion: _package.Manifest.ComplianceEnvelope.DeclaredModuleVersion,
            IssuedAtUtc: DateTimeOffset.UtcNow);

        return statement.ToUtf8Bytes();
    }

    private void RequireAdvertisedAlgorithm(AlgorithmId algorithmId, string operation)
    {
        if (!_advertisedAlgorithms.Contains(algorithmId.Value))
            throw new OopProtocolException($"{operation} rejected because algorithm '{algorithmId.Value}' is not advertised by this provider instance.");
    }

    private void EnsurePrivateKeyHandleProvider(PrivateKeyHandle handle, string operation)
        => EnsureHandleProvider(handle.ProviderId, operation, "PrivateKeyHandle");

    private void EnsureSecretKeyHandleProvider(SecretKeyHandle handle, string operation)
        => EnsureHandleProvider(handle.ProviderId, operation, "SecretKeyHandle");

    private void EnsureSharedSecretHandleProvider(SharedSecretHandle handle, string operation)
        => EnsureHandleProvider(handle.ProviderId, operation, "SharedSecretHandle");

    private void EnsureHandleProvider(ProviderId handleProviderId, string operation, string handleKind)
    {
        if (!_identity.ProviderId.Equals(handleProviderId))
        {
            throw new OopProtocolException(
                $"{operation} request provider mismatch for {handleKind}. Expected provider '{_identity.ProviderId.Value}', got '{handleProviderId.Value}'.");
        }
    }

    private static bool IsMlKemAlgorithm(AlgorithmId algorithmId)
        => algorithmId.Value is "ML-KEM-512" or "ML-KEM-768" or "ML-KEM-1024";

    private static bool IsMlDsaAlgorithm(AlgorithmId algorithmId)
        => algorithmId.Value is "ML-DSA-44" or "ML-DSA-65" or "ML-DSA-87";

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    private void ThrowIfDisposedOrShutdown()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_shutdown)
            throw new OopProtocolException("Provider is shutting down.");
    }
}
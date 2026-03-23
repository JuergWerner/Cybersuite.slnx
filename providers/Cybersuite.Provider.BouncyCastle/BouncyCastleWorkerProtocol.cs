using System;
using System.Buffers.Binary;
using System.IO;
using System.Text.Json;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Headers;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Shared protocol helpers for the Wave 4 BouncyCastle out-of-process worker.
/// The transport is deliberately simple: length-prefixed JSON frames over stdio.
/// </summary>
public static class BouncyCastleWorkerProtocol
{
    public const string BootstrapEnvironmentVariableName = "CYBERSUITE_PROVIDER_BOOTSTRAP";

    public const string HandshakeOperation = "handshake";
    public const string CapabilityOperation = "capabilities";
    public const string HealthOperation = "health";
    public const string ShutdownOperation = "shutdown";
    public const string KemGenerateKeyPairOperation = "kem_generate_keypair";
    public const string KemEncapsulateOperation = "kem_encapsulate";
    public const string KemDecapsulateOperation = "kem_decapsulate";
    public const string SignatureGenerateKeyPairOperation = "signature_generate_keypair";
    public const string SignatureSignOperation = "signature_sign";
    public const string SignatureVerifyOperation = "signature_verify";
    public const string AeadGenerateKeyOperation = "aead_generate_key";
    public const string AeadEncryptOperation = "aead_encrypt";
    public const string AeadDecryptOperation = "aead_decrypt";
    public const string KdfDeriveKeyOperation = "kdf_derive_key";
    public const string DestroyHandleOperation = "destroy_handle";

    public static JsonSerializerOptions JsonOptions { get; } = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    public static async ValueTask WriteFrameAsync(Stream stream, BouncyCastleWorkerFrame frame, CancellationToken cancellationToken)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(frame, JsonOptions);
        try
        {
            byte[] length = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(length, json.Length);
            await stream.WriteAsync(length, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(json, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            Array.Clear(json, 0, json.Length);
        }
    }

    public static async ValueTask<BouncyCastleWorkerFrame> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        byte[] lengthBytes = await ReadExactAsync(stream, 4, cancellationToken).ConfigureAwait(false);
        try
        {
            int length = BinaryPrimitives.ReadInt32BigEndian(lengthBytes);
            if (length <= 0 || length > 16 * 1024 * 1024)
                throw new InvalidOperationException("Worker frame length is invalid.");

            byte[] json = await ReadExactAsync(stream, length, cancellationToken).ConfigureAwait(false);
            try
            {
                return JsonSerializer.Deserialize<BouncyCastleWorkerFrame>(json, JsonOptions)
                    ?? throw new InvalidOperationException("Worker frame deserialization returned null.");
            }
            finally
            {
                Array.Clear(json, 0, json.Length);
            }
        }
        finally
        {
            Array.Clear(lengthBytes, 0, lengthBytes.Length);
        }
    }

    public static string SerializePayload<T>(T payload)
        => JsonSerializer.Serialize(payload, JsonOptions);

    public static T DeserializePayload<T>(string? payloadJson)
        => JsonSerializer.Deserialize<T>(payloadJson ?? throw new InvalidOperationException("Worker payload is missing."), JsonOptions)
            ?? throw new InvalidOperationException($"Worker payload deserialization for '{typeof(T).Name}' returned null.");

    public static BouncyCastleWorkerBootstrapDto ToBootstrapDto(ProviderPackage package)
        => new(ToDto(package));

    public static ProviderPackage ToPackage(BouncyCastleWorkerBootstrapDto dto)
        => ToProviderPackage(dto.Package);

    public static ProviderPackageDto ToDto(ProviderPackage package)
        => new(
            PackageRoot: package.PackageRoot,
            EntrypointPath: package.EntrypointPath,
            Manifest: ToDto(package.Manifest));

    public static ProviderPackage ToProviderPackage(ProviderPackageDto dto)
        => new()
        {
            PackageRoot = dto.PackageRoot,
            EntrypointPath = dto.EntrypointPath,
            Manifest = ToProviderManifest(dto.Manifest)
        };

    public static ProviderManifestDto ToDto(ProviderManifest manifest)
        => new(
            ProviderId: manifest.ProviderId.Value,
            Version: manifest.Version,
            Vendor: manifest.Vendor,
            IsolationMode: manifest.IsolationMode,
            IsExperimental: manifest.IsExperimental,
            FipsBoundaryDeclared: manifest.FipsBoundaryDeclared,
            ComplianceEnvelope: ToDto(manifest.ComplianceEnvelope),
            EntrypointSha256Hex: manifest.EntrypointSha256Hex,
            SignatureBundleBase64: manifest.SignatureBundleBase64,
            ReleaseBundleBase64: manifest.ReleaseBundleBase64);

    public static ProviderManifest ToProviderManifest(ProviderManifestDto dto)
        => new()
        {
            ProviderId = new ProviderId(dto.ProviderId),
            Version = dto.Version,
            Vendor = dto.Vendor,
            IsolationMode = dto.IsolationMode,
            IsExperimental = dto.IsExperimental,
            FipsBoundaryDeclared = dto.FipsBoundaryDeclared,
            ComplianceEnvelope = ToProviderComplianceEnvelope(dto.ComplianceEnvelope),
            EntrypointSha256Hex = dto.EntrypointSha256Hex,
            SignatureBundleBase64 = dto.SignatureBundleBase64,
            ReleaseBundleBase64 = dto.ReleaseBundleBase64
        };

    public static VersionDto ToDto(ProtocolVersion version)
        => new(version.Major, version.Minor);

    public static ProtocolVersion ToProtocolVersion(VersionDto dto)
        => new(dto.Major, dto.Minor);

    public static Handle128Dto ToDto(Handle128 handle)
        => new(handle.High, handle.Low);

    public static Handle128 ToHandle128(Handle128Dto dto)
        => new(dto.High, dto.Low);

    public static OopErrorDto? ToDto(OopError? error)
        => error is null ? null : new(error.Code, error.Message);

    public static OopError? ToOopError(OopErrorDto? dto)
        => dto is null ? null : new OopError(dto.Code, dto.Message);

    public static OopRequestHeaderDto ToDto(OopRequestHeader header)
        => new(
            Version: ToDto(header.Version),
            MessageType: header.MessageType,
            RequestId: ToDto(header.RequestId),
            MessageCounter: header.MessageCounter,
            ChannelBindingSha384: header.ChannelBindingSha384.ToArray());

    public static OopRequestHeader ToOopRequestHeader(OopRequestHeaderDto dto)
        => new(
            version: ToProtocolVersion(dto.Version),
            messageType: dto.MessageType,
            requestId: ToHandle128(dto.RequestId),
            messageCounter: dto.MessageCounter,
            channelBindingSha384: dto.ChannelBindingSha384);

    public static OopResponseHeaderDto ToDto(OopResponseHeader header)
        => new(
            Version: ToDto(header.Version),
            MessageType: header.MessageType,
            RequestId: ToDto(header.RequestId),
            MessageCounter: header.MessageCounter,
            ChannelBindingSha384: header.ChannelBindingSha384.ToArray(),
            Success: header.Success,
            Error: ToDto(header.Error));

    public static OopResponseHeader ToOopResponseHeader(OopResponseHeaderDto dto)
        => new(
            version: ToProtocolVersion(dto.Version),
            messageType: dto.MessageType,
            requestId: ToHandle128(dto.RequestId),
            messageCounter: dto.MessageCounter,
            channelBindingSha384: dto.ChannelBindingSha384,
            success: dto.Success,
            error: ToOopError(dto.Error));

    public static ProviderComplianceEnvelopeDto ToDto(ProviderComplianceEnvelope envelope)
        => new(
            SecurityClass: envelope.SecurityClass,
            BoundaryClass: envelope.BoundaryClass,
            DeclaredValidatedBoundary: envelope.DeclaredValidatedBoundary,
            DeclaredModuleName: envelope.DeclaredModuleName,
            DeclaredCertificateReference: envelope.DeclaredCertificateReference,
            DeclaredModuleVersion: envelope.DeclaredModuleVersion,
            SupportsNonExportableKeys: envelope.SupportsNonExportableKeys,
            SupportsRawSecretEgress: envelope.SupportsRawSecretEgress,
            AttestationMode: envelope.AttestationMode);

    public static ProviderComplianceEnvelope ToProviderComplianceEnvelope(ProviderComplianceEnvelopeDto dto)
        => new(
            securityClass: dto.SecurityClass,
            boundaryClass: dto.BoundaryClass,
            declaredValidatedBoundary: dto.DeclaredValidatedBoundary,
            declaredModuleName: dto.DeclaredModuleName,
            declaredCertificateReference: dto.DeclaredCertificateReference,
            declaredModuleVersion: dto.DeclaredModuleVersion,
            supportsNonExportableKeys: dto.SupportsNonExportableKeys,
            supportsRawSecretEgress: dto.SupportsRawSecretEgress,
            attestationMode: dto.AttestationMode);

    public static ProviderIdentityDto ToDto(ProviderIdentity identity)
        => new(identity.ProviderId.Value, identity.Version, identity.BuildHash, identity.SignatureFingerprint);

    public static ProviderIdentity ToProviderIdentity(ProviderIdentityDto dto)
        => new(new ProviderId(dto.ProviderId), dto.Version, dto.BuildHash, dto.SignatureFingerprint);

    public static ClientHelloDto ToDto(ClientHello hello)
        => new(
            Version: ToDto(hello.Version),
            Nonce: hello.Nonce.ToArray(),
            PolicyHashSha384: hello.PolicyHashSha384.ToArray(),
            Profile: hello.Profile,
            FipsRequired: hello.FipsRequired,
            ExperimentalAllowed: hello.ExperimentalAllowed,
            TenantId: hello.TenantId,
            ExpectedProviderId: hello.ExpectedProviderId,
            ExpectedBuildHash: hello.ExpectedBuildHash);

    public static ClientHello ToClientHello(ClientHelloDto dto)
        => new(
            version: ToProtocolVersion(dto.Version),
            nonce32: dto.Nonce,
            policyHashSha384: dto.PolicyHashSha384,
            profile: dto.Profile,
            fipsRequired: dto.FipsRequired,
            experimentalAllowed: dto.ExperimentalAllowed,
            tenantId: dto.TenantId,
            expectedProviderId: dto.ExpectedProviderId,
            expectedBuildHash: dto.ExpectedBuildHash);

    public static ProviderHelloDto ToDto(ProviderHello hello)
        => new(
            Version: ToDto(hello.Version),
            Nonce: hello.Nonce.ToArray(),
            Identity: ToDto(hello.Identity),
            CapabilityHashSha384: hello.CapabilityHashSha384.ToArray(),
            ComplianceEnvelope: ToDto(hello.ComplianceEnvelope),
            FipsBoundaryDeclared: hello.FipsBoundaryDeclared,
            IsExperimental: hello.IsExperimental,
            AttestationEvidence: hello.AttestationEvidence?.ToArray());

    public static ProviderHello ToProviderHello(ProviderHelloDto dto)
        => new(
            version: ToProtocolVersion(dto.Version),
            nonce32: dto.Nonce,
            identity: ToProviderIdentity(dto.Identity),
            capabilityHashSha384: dto.CapabilityHashSha384,
            complianceEnvelope: ToProviderComplianceEnvelope(dto.ComplianceEnvelope),
            isExperimental: dto.IsExperimental,
            attestationEvidence: dto.AttestationEvidence);

    public static PublicKeyDto ToDto(PublicKey value)
        => new(value.AlgorithmId.Value, value.Bytes.ToArray());

    public static PublicKey ToPublicKey(PublicKeyDto dto)
        => new(new AlgorithmId(dto.AlgorithmId), dto.Bytes);

    public static PrivateKeyHandleDto ToDto(PrivateKeyHandle value)
        => new(value.ProviderId.Value, value.Value);

    public static PrivateKeyHandle ToPrivateKeyHandle(PrivateKeyHandleDto dto)
        => new(new ProviderId(dto.ProviderId), dto.Value);

    public static SecretKeyHandleDto ToDto(SecretKeyHandle value)
        => new(value.ProviderId.Value, value.Value);

    public static SecretKeyHandle ToSecretKeyHandle(SecretKeyHandleDto dto)
        => new(new ProviderId(dto.ProviderId), dto.Value);

    public static SharedSecretHandleDto ToDto(SharedSecretHandle value)
        => new(value.ProviderId.Value, value.Value);

    public static SharedSecretHandle ToSharedSecretHandle(SharedSecretHandleDto dto)
        => new(new ProviderId(dto.ProviderId), dto.Value);

    public static KemKeyPairDto ToDto(KemKeyPair value)
        => new(ToDto(value.PublicKey), ToDto(value.PrivateKey));

    public static KemKeyPair ToKemKeyPair(KemKeyPairDto dto)
        => new(ToPublicKey(dto.PublicKey), ToPrivateKeyHandle(dto.PrivateKey));

    public static SignatureKeyPairDto ToDto(SignatureKeyPair value)
        => new(ToDto(value.PublicKey), ToDto(value.PrivateKey));

    public static SignatureKeyPair ToSignatureKeyPair(SignatureKeyPairDto dto)
        => new(ToPublicKey(dto.PublicKey), ToPrivateKeyHandle(dto.PrivateKey));

    public static KemEncapsulationResultDto ToDto(KemEncapsulationResult value)
        => new(value.Ciphertext.ToArray(), ToDto(value.SharedSecret));

    public static KemEncapsulationResult ToKemEncapsulationResult(KemEncapsulationResultDto dto)
        => new(dto.Ciphertext, ToSharedSecretHandle(dto.SharedSecret));

    public static KdfParametersDto ToDto(KdfParameters value)
        => new(value.Salt.ToArray(), value.Info.ToArray(), value.OutputKeyBits);

    public static KdfParameters ToKdfParameters(KdfParametersDto dto)
        => new(dto.Salt, dto.Info, dto.OutputKeyBits);

    public static CapabilityRequestDto ToDto(CapabilityRequest request) => new(ToDto(request.Header));
    public static CapabilityRequest ToCapabilityRequest(CapabilityRequestDto dto) => new(ToOopRequestHeader(dto.Header));

    public static CapabilityResponseDto ToDto(CapabilityResponse response)
        => new(ToDto(response.Header), response.CapabilityCanonicalBytes.ToArray(), response.CapabilityHashSha384.ToArray());
    public static CapabilityResponse ToCapabilityResponse(CapabilityResponseDto dto)
        => new(ToOopResponseHeader(dto.Header), dto.CapabilityCanonicalBytes, dto.CapabilityHashSha384);

    public static HealthRequestDto ToDto(HealthRequest request) => new(ToDto(request.Header));
    public static HealthRequest ToHealthRequest(HealthRequestDto dto) => new(ToOopRequestHeader(dto.Header));

    public static HealthResponseDto ToDto(HealthResponse response) => new(ToDto(response.Header), response.IsHealthy);
    public static HealthResponse ToHealthResponse(HealthResponseDto dto) => new(ToOopResponseHeader(dto.Header), dto.IsHealthy);

    public static ShutdownRequestDto ToDto(ShutdownRequest request) => new(ToDto(request.Header), request.Graceful);
    public static ShutdownRequest ToShutdownRequest(ShutdownRequestDto dto) => new(ToOopRequestHeader(dto.Header), dto.Graceful);

    public static ShutdownResponseDto ToDto(ShutdownResponse response) => new(ToDto(response.Header));
    public static ShutdownResponse ToShutdownResponse(ShutdownResponseDto dto) => new(ToOopResponseHeader(dto.Header));

    public static KemGenerateKeyPairRequestDto ToDto(KemGenerateKeyPairRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value);
    public static KemGenerateKeyPairRequest ToKemGenerateKeyPairRequest(KemGenerateKeyPairRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId));
    public static KemGenerateKeyPairResponseDto ToDto(KemGenerateKeyPairResponse response) => new(ToDto(response.Header), ToDto(response.KeyPair));
    public static KemGenerateKeyPairResponse ToKemGenerateKeyPairResponse(KemGenerateKeyPairResponseDto dto) => new(ToOopResponseHeader(dto.Header), ToKemKeyPair(dto.KeyPair));

    public static KemEncapsulateRequestDto ToDto(KemEncapsulateRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value, ToDto(request.RecipientPublicKey));
    public static KemEncapsulateRequest ToKemEncapsulateRequest(KemEncapsulateRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId), ToPublicKey(dto.RecipientPublicKey));
    public static KemEncapsulateResponseDto ToDto(KemEncapsulateResponse response) => new(ToDto(response.Header), ToDto(response.Result));
    public static KemEncapsulateResponse ToKemEncapsulateResponse(KemEncapsulateResponseDto dto) => new(ToOopResponseHeader(dto.Header), ToKemEncapsulationResult(dto.Result));

    public static KemDecapsulateRequestDto ToDto(KemDecapsulateRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value, ToDto(request.PrivateKey), request.Ciphertext.ToArray());
    public static KemDecapsulateRequest ToKemDecapsulateRequest(KemDecapsulateRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId), ToPrivateKeyHandle(dto.PrivateKey), dto.Ciphertext);
    public static KemDecapsulateResponseDto ToDto(KemDecapsulateResponse response) => new(ToDto(response.Header), ToDto(response.SharedSecret));
    public static KemDecapsulateResponse ToKemDecapsulateResponse(KemDecapsulateResponseDto dto) => new(ToOopResponseHeader(dto.Header), ToSharedSecretHandle(dto.SharedSecret));

    public static SignatureGenerateKeyPairRequestDto ToDto(SignatureGenerateKeyPairRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value);
    public static SignatureGenerateKeyPairRequest ToSignatureGenerateKeyPairRequest(SignatureGenerateKeyPairRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId));
    public static SignatureGenerateKeyPairResponseDto ToDto(SignatureGenerateKeyPairResponse response) => new(ToDto(response.Header), ToDto(response.KeyPair));
    public static SignatureGenerateKeyPairResponse ToSignatureGenerateKeyPairResponse(SignatureGenerateKeyPairResponseDto dto) => new(ToOopResponseHeader(dto.Header), ToSignatureKeyPair(dto.KeyPair));

    public static SignatureSignRequestDto ToDto(SignatureSignRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value, ToDto(request.PrivateKey), request.Message.ToArray());
    public static SignatureSignRequest ToSignatureSignRequest(SignatureSignRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId), ToPrivateKeyHandle(dto.PrivateKey), dto.Message);
    public static SignatureSignResponseDto ToDto(SignatureSignResponse response) => new(ToDto(response.Header), response.Signature.ToArray());
    public static SignatureSignResponse ToSignatureSignResponse(SignatureSignResponseDto dto) => new(ToOopResponseHeader(dto.Header), dto.Signature);

    public static SignatureVerifyRequestDto ToDto(SignatureVerifyRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value, ToDto(request.PublicKey), request.Message.ToArray(), request.Signature.ToArray());
    public static SignatureVerifyRequest ToSignatureVerifyRequest(SignatureVerifyRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId), ToPublicKey(dto.PublicKey), dto.Message, dto.Signature);
    public static SignatureVerifyResponseDto ToDto(SignatureVerifyResponse response) => new(ToDto(response.Header), response.IsValid);
    public static SignatureVerifyResponse ToSignatureVerifyResponse(SignatureVerifyResponseDto dto) => new(ToOopResponseHeader(dto.Header), dto.IsValid);

    public static AeadGenerateKeyRequestDto ToDto(AeadGenerateKeyRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value);
    public static AeadGenerateKeyRequest ToAeadGenerateKeyRequest(AeadGenerateKeyRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId));
    public static AeadGenerateKeyResponseDto ToDto(AeadGenerateKeyResponse response) => new(ToDto(response.Header), ToDto(response.KeyHandle));
    public static AeadGenerateKeyResponse ToAeadGenerateKeyResponse(AeadGenerateKeyResponseDto dto) => new(ToOopResponseHeader(dto.Header), ToSecretKeyHandle(dto.KeyHandle));

    public static AeadEncryptRequestDto ToDto(AeadEncryptRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value, ToDto(request.KeyHandle), request.Nonce.ToArray(), request.Plaintext.ToArray(), request.AssociatedData.ToArray());
    public static AeadEncryptRequest ToAeadEncryptRequest(AeadEncryptRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId), ToSecretKeyHandle(dto.KeyHandle), dto.Nonce, dto.Plaintext, dto.AssociatedData);
    public static AeadEncryptResponseDto ToDto(AeadEncryptResponse response) => new(ToDto(response.Header), response.Ciphertext.ToArray());
    public static AeadEncryptResponse ToAeadEncryptResponse(AeadEncryptResponseDto dto) => new(ToOopResponseHeader(dto.Header), dto.Ciphertext);

    public static AeadDecryptRequestDto ToDto(AeadDecryptRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value, ToDto(request.KeyHandle), request.Nonce.ToArray(), request.Ciphertext.ToArray(), request.AssociatedData.ToArray());
    public static AeadDecryptRequest ToAeadDecryptRequest(AeadDecryptRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId), ToSecretKeyHandle(dto.KeyHandle), dto.Nonce, dto.Ciphertext, dto.AssociatedData);
    public static AeadDecryptResponseDto ToDto(AeadDecryptResponse response) => new(ToDto(response.Header), response.IsValid, response.Plaintext.ToArray());
    public static AeadDecryptResponse ToAeadDecryptResponse(AeadDecryptResponseDto dto) => new(ToOopResponseHeader(dto.Header), dto.IsValid, dto.Plaintext);

    public static KdfDeriveKeyRequestDto ToDto(KdfDeriveKeyRequest request) => new(ToDto(request.Header), request.AlgorithmId.Value, ToDto(request.SharedSecretHandle), ToDto(request.Parameters));
    public static KdfDeriveKeyRequest ToKdfDeriveKeyRequest(KdfDeriveKeyRequestDto dto) => new(ToOopRequestHeader(dto.Header), new AlgorithmId(dto.AlgorithmId), ToSharedSecretHandle(dto.SharedSecretHandle), ToKdfParameters(dto.Parameters));
    public static KdfDeriveKeyResponseDto ToDto(KdfDeriveKeyResponse response) => new(ToDto(response.Header), ToDto(response.SecretKeyHandle));
    public static KdfDeriveKeyResponse ToKdfDeriveKeyResponse(KdfDeriveKeyResponseDto dto) => new(ToOopResponseHeader(dto.Header), ToSecretKeyHandle(dto.SecretKeyHandle));

    public static DestroyHandleRequestDto ToDto(DestroyHandleRequest request) => new(ToDto(request.Header), request.Kind, request.ProviderId.Value, request.HandleValue);
    public static DestroyHandleRequest ToDestroyHandleRequest(DestroyHandleRequestDto dto) => new(ToOopRequestHeader(dto.Header), dto.Kind, new ProviderId(dto.ProviderId), dto.HandleValue);
    public static DestroyHandleResponseDto ToDto(DestroyHandleResponse response) => new(ToDto(response.Header));
    public static DestroyHandleResponse ToDestroyHandleResponse(DestroyHandleResponseDto dto) => new(ToOopResponseHeader(dto.Header));

    private static async ValueTask<byte[]> ReadExactAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        byte[] buffer = new byte[length];
        int offset = 0;
        while (offset < length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken).ConfigureAwait(false);
            if (read == 0)
                throw new EndOfStreamException("Unexpected end of worker stream.");
            offset += read;
        }

        return buffer;
    }
}

public sealed record BouncyCastleWorkerFrame(string Operation, string? PayloadJson, bool Success = true, string? ErrorCode = null, string? ErrorMessage = null);
public sealed record BouncyCastleWorkerBootstrapDto(ProviderPackageDto Package);
public sealed record ProviderPackageDto(string PackageRoot, string EntrypointPath, ProviderManifestDto Manifest);
public sealed record ProviderManifestDto(string ProviderId, string Version, string Vendor, ProviderIsolationMode IsolationMode, bool IsExperimental, bool FipsBoundaryDeclared, ProviderComplianceEnvelopeDto ComplianceEnvelope, string? EntrypointSha256Hex, string? SignatureBundleBase64, string? ReleaseBundleBase64);
public sealed record VersionDto(ushort Major, ushort Minor);
public sealed record Handle128Dto(ulong High, ulong Low);
public sealed record OopErrorDto(OopErrorCode Code, string Message);
public sealed record OopRequestHeaderDto(VersionDto Version, OopMessageType MessageType, Handle128Dto RequestId, ulong MessageCounter, byte[] ChannelBindingSha384);
public sealed record OopResponseHeaderDto(VersionDto Version, OopMessageType MessageType, Handle128Dto RequestId, ulong MessageCounter, byte[] ChannelBindingSha384, bool Success, OopErrorDto? Error);
public sealed record ProviderComplianceEnvelopeDto(ProviderSecurityClass SecurityClass, RequiredBoundaryClass BoundaryClass, bool DeclaredValidatedBoundary, string? DeclaredModuleName, string? DeclaredCertificateReference, string? DeclaredModuleVersion, bool SupportsNonExportableKeys, bool SupportsRawSecretEgress, AttestationMode AttestationMode);
public sealed record ProviderIdentityDto(string ProviderId, string Version, string BuildHash, string? SignatureFingerprint);
public sealed record ClientHelloDto(VersionDto Version, byte[] Nonce, byte[] PolicyHashSha384, ExecutionProfile Profile, bool FipsRequired, bool ExperimentalAllowed, string? TenantId, string? ExpectedProviderId, string? ExpectedBuildHash);
public sealed record ProviderHelloDto(VersionDto Version, byte[] Nonce, ProviderIdentityDto Identity, byte[] CapabilityHashSha384, ProviderComplianceEnvelopeDto ComplianceEnvelope, bool FipsBoundaryDeclared, bool IsExperimental, byte[]? AttestationEvidence);
public sealed record PublicKeyDto(string AlgorithmId, byte[] Bytes);
public sealed record PrivateKeyHandleDto(string ProviderId, Guid Value);
public sealed record SecretKeyHandleDto(string ProviderId, Guid Value);
public sealed record SharedSecretHandleDto(string ProviderId, Guid Value);
public sealed record KemKeyPairDto(PublicKeyDto PublicKey, PrivateKeyHandleDto PrivateKey);
public sealed record SignatureKeyPairDto(PublicKeyDto PublicKey, PrivateKeyHandleDto PrivateKey);
public sealed record KemEncapsulationResultDto(byte[] Ciphertext, SharedSecretHandleDto SharedSecret);
public sealed record KdfParametersDto(byte[] Salt, byte[] Info, int OutputKeyBits);
public sealed record CapabilityRequestDto(OopRequestHeaderDto Header);
public sealed record CapabilityResponseDto(OopResponseHeaderDto Header, byte[] CapabilityCanonicalBytes, byte[] CapabilityHashSha384);
public sealed record HealthRequestDto(OopRequestHeaderDto Header);
public sealed record HealthResponseDto(OopResponseHeaderDto Header, bool IsHealthy);
public sealed record ShutdownRequestDto(OopRequestHeaderDto Header, bool Graceful);
public sealed record ShutdownResponseDto(OopResponseHeaderDto Header);
public sealed record KemGenerateKeyPairRequestDto(OopRequestHeaderDto Header, string AlgorithmId);
public sealed record KemGenerateKeyPairResponseDto(OopResponseHeaderDto Header, KemKeyPairDto KeyPair);
public sealed record KemEncapsulateRequestDto(OopRequestHeaderDto Header, string AlgorithmId, PublicKeyDto RecipientPublicKey);
public sealed record KemEncapsulateResponseDto(OopResponseHeaderDto Header, KemEncapsulationResultDto Result);
public sealed record KemDecapsulateRequestDto(OopRequestHeaderDto Header, string AlgorithmId, PrivateKeyHandleDto PrivateKey, byte[] Ciphertext);
public sealed record KemDecapsulateResponseDto(OopResponseHeaderDto Header, SharedSecretHandleDto SharedSecret);
public sealed record SignatureGenerateKeyPairRequestDto(OopRequestHeaderDto Header, string AlgorithmId);
public sealed record SignatureGenerateKeyPairResponseDto(OopResponseHeaderDto Header, SignatureKeyPairDto KeyPair);
public sealed record SignatureSignRequestDto(OopRequestHeaderDto Header, string AlgorithmId, PrivateKeyHandleDto PrivateKey, byte[] Message);
public sealed record SignatureSignResponseDto(OopResponseHeaderDto Header, byte[] Signature);
public sealed record SignatureVerifyRequestDto(OopRequestHeaderDto Header, string AlgorithmId, PublicKeyDto PublicKey, byte[] Message, byte[] Signature);
public sealed record SignatureVerifyResponseDto(OopResponseHeaderDto Header, bool IsValid);
public sealed record AeadGenerateKeyRequestDto(OopRequestHeaderDto Header, string AlgorithmId);
public sealed record AeadGenerateKeyResponseDto(OopResponseHeaderDto Header, SecretKeyHandleDto KeyHandle);
public sealed record AeadEncryptRequestDto(OopRequestHeaderDto Header, string AlgorithmId, SecretKeyHandleDto KeyHandle, byte[] Nonce, byte[] Plaintext, byte[] AssociatedData);
public sealed record AeadEncryptResponseDto(OopResponseHeaderDto Header, byte[] Ciphertext);
public sealed record AeadDecryptRequestDto(OopRequestHeaderDto Header, string AlgorithmId, SecretKeyHandleDto KeyHandle, byte[] Nonce, byte[] Ciphertext, byte[] AssociatedData);
public sealed record AeadDecryptResponseDto(OopResponseHeaderDto Header, bool IsValid, byte[] Plaintext);
public sealed record KdfDeriveKeyRequestDto(OopRequestHeaderDto Header, string AlgorithmId, SharedSecretHandleDto SharedSecretHandle, KdfParametersDto Parameters);
public sealed record KdfDeriveKeyResponseDto(OopResponseHeaderDto Header, SecretKeyHandleDto SecretKeyHandle);
public sealed record DestroyHandleRequestDto(OopRequestHeaderDto Header, DestroyHandleKind Kind, string ProviderId, Guid HandleValue);
public sealed record DestroyHandleResponseDto(OopResponseHeaderDto Header);

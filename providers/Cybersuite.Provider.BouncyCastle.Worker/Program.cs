using System;
using System.IO;
using System.Text.Json;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.Provider.BouncyCastle;
using Cybersuite.ProviderHost;

namespace Cybersuite.Provider.BouncyCastle.Worker;

internal static class Program
{
    public static async Task<int> Main()
    {
        try
        {
            ProviderPackage package = LoadPackageFromBootstrap();

            await using IProviderConnection connection = new BouncyCastleProviderConnection(package);
            using Stream stdin = Console.OpenStandardInput();
            using Stream stdout = Console.OpenStandardOutput();

            while (true)
            {
                BouncyCastleWorkerFrame request = await BouncyCastleWorkerProtocol.ReadFrameAsync(stdin, CancellationToken.None).ConfigureAwait(false);
                BouncyCastleWorkerFrame response;
                try
                {
                    response = await DispatchAsync(connection, request, CancellationToken.None).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    response = new BouncyCastleWorkerFrame(
                        Operation: request.Operation,
                        PayloadJson: null,
                        Success: false,
                        ErrorCode: "worker_exception",
                        ErrorMessage: ex.Message);
                }

                await BouncyCastleWorkerProtocol.WriteFrameAsync(stdout, response, CancellationToken.None).ConfigureAwait(false);

                if (string.Equals(request.Operation, BouncyCastleWorkerProtocol.ShutdownOperation, StringComparison.Ordinal) && response.Success)
                    break;
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Cybersuite.Provider.BouncyCastle.Worker fatal: {ex.Message}");
            return 1;
        }
    }

    private static ProviderPackage LoadPackageFromBootstrap()
    {
        string? bootstrapBase64 = Environment.GetEnvironmentVariable(BouncyCastleWorkerProtocol.BootstrapEnvironmentVariableName);
        if (string.IsNullOrWhiteSpace(bootstrapBase64))
            throw new InvalidOperationException($"Missing bootstrap environment variable '{BouncyCastleWorkerProtocol.BootstrapEnvironmentVariableName}'.");

        byte[] bootstrapBytes = Convert.FromBase64String(bootstrapBase64);
        try
        {
            BouncyCastleWorkerBootstrapDto bootstrap = JsonSerializer.Deserialize<BouncyCastleWorkerBootstrapDto>(bootstrapBytes, BouncyCastleWorkerProtocol.JsonOptions)
                ?? throw new InvalidOperationException("Worker bootstrap deserialization returned null.");

            return BouncyCastleWorkerProtocol.ToPackage(bootstrap);
        }
        finally
        {
            Array.Clear(bootstrapBytes, 0, bootstrapBytes.Length);
        }
    }

    private static ValueTask<BouncyCastleWorkerFrame> DispatchAsync(
        IProviderConnection connection,
        BouncyCastleWorkerFrame request,
        CancellationToken cancellationToken)
    {
        return request.Operation switch
        {
            var op when op == BouncyCastleWorkerProtocol.HandshakeOperation => InvokeAsync<ClientHelloDto, ClientHello, ProviderHello, ProviderHelloDto>(
                request,
                BouncyCastleWorkerProtocol.ToClientHello,
                connection.HandshakeAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.CapabilityOperation => InvokeAsync<CapabilityRequestDto, CapabilityRequest, CapabilityResponse, CapabilityResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToCapabilityRequest,
                connection.GetCapabilitiesAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.HealthOperation => InvokeAsync<HealthRequestDto, HealthRequest, HealthResponse, HealthResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToHealthRequest,
                connection.HealthAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.ShutdownOperation => InvokeAsync<ShutdownRequestDto, ShutdownRequest, ShutdownResponse, ShutdownResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToShutdownRequest,
                connection.ShutdownAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.KemGenerateKeyPairOperation => InvokeAsync<KemGenerateKeyPairRequestDto, KemGenerateKeyPairRequest, KemGenerateKeyPairResponse, KemGenerateKeyPairResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToKemGenerateKeyPairRequest,
                connection.KemGenerateKeyPairAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.KemEncapsulateOperation => InvokeAsync<KemEncapsulateRequestDto, KemEncapsulateRequest, KemEncapsulateResponse, KemEncapsulateResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToKemEncapsulateRequest,
                connection.KemEncapsulateAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.KemDecapsulateOperation => InvokeAsync<KemDecapsulateRequestDto, KemDecapsulateRequest, KemDecapsulateResponse, KemDecapsulateResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToKemDecapsulateRequest,
                connection.KemDecapsulateAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.SignatureGenerateKeyPairOperation => InvokeAsync<SignatureGenerateKeyPairRequestDto, SignatureGenerateKeyPairRequest, SignatureGenerateKeyPairResponse, SignatureGenerateKeyPairResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToSignatureGenerateKeyPairRequest,
                connection.SignatureGenerateKeyPairAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.SignatureSignOperation => InvokeAsync<SignatureSignRequestDto, SignatureSignRequest, SignatureSignResponse, SignatureSignResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToSignatureSignRequest,
                connection.SignatureSignAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.SignatureVerifyOperation => InvokeAsync<SignatureVerifyRequestDto, SignatureVerifyRequest, SignatureVerifyResponse, SignatureVerifyResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToSignatureVerifyRequest,
                connection.SignatureVerifyAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.AeadGenerateKeyOperation => InvokeAsync<AeadGenerateKeyRequestDto, AeadGenerateKeyRequest, AeadGenerateKeyResponse, AeadGenerateKeyResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToAeadGenerateKeyRequest,
                connection.AeadGenerateKeyAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.AeadEncryptOperation => InvokeAsync<AeadEncryptRequestDto, AeadEncryptRequest, AeadEncryptResponse, AeadEncryptResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToAeadEncryptRequest,
                connection.AeadEncryptAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.AeadDecryptOperation => InvokeAsync<AeadDecryptRequestDto, AeadDecryptRequest, AeadDecryptResponse, AeadDecryptResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToAeadDecryptRequest,
                connection.AeadDecryptAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.KdfDeriveKeyOperation => InvokeAsync<KdfDeriveKeyRequestDto, KdfDeriveKeyRequest, KdfDeriveKeyResponse, KdfDeriveKeyResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToKdfDeriveKeyRequest,
                connection.KdfDeriveKeyAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            var op when op == BouncyCastleWorkerProtocol.DestroyHandleOperation => InvokeAsync<DestroyHandleRequestDto, DestroyHandleRequest, DestroyHandleResponse, DestroyHandleResponseDto>(
                request,
                BouncyCastleWorkerProtocol.ToDestroyHandleRequest,
                connection.DestroyHandleAsync,
                BouncyCastleWorkerProtocol.ToDto,
                cancellationToken),

            _ => ValueTask.FromResult(
                new BouncyCastleWorkerFrame(
                    Operation: request.Operation,
                    PayloadJson: null,
                    Success: false,
                    ErrorCode: "unknown_operation",
                    ErrorMessage: $"Unknown worker operation '{request.Operation}'."))
        };
    }

    private static async ValueTask<BouncyCastleWorkerFrame> InvokeAsync<TRequestDto, TRequest, TResponse, TResponseDto>(
        BouncyCastleWorkerFrame requestFrame,
        Func<TRequestDto, TRequest> toRequest,
        Func<TRequest, CancellationToken, ValueTask<TResponse>> invoke,
        Func<TResponse, TResponseDto> toResponseDto,
        CancellationToken cancellationToken)
    {
        TRequestDto requestDto = BouncyCastleWorkerProtocol.DeserializePayload<TRequestDto>(requestFrame.PayloadJson);
        TRequest request = toRequest(requestDto);
        TResponse response = await invoke(request, cancellationToken).ConfigureAwait(false);
        TResponseDto responseDto = toResponseDto(response);

        return new BouncyCastleWorkerFrame(
            Operation: requestFrame.Operation,
            PayloadJson: BouncyCastleWorkerProtocol.SerializePayload(responseDto),
            Success: true,
            ErrorCode: null,
            ErrorMessage: null);
    }
}

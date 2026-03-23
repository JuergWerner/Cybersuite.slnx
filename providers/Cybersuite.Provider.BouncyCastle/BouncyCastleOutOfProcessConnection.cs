using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.OopProtocol;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.OopProtocol.Messages;
using Cybersuite.ProviderHost;
using Cybersuite.ProviderHost.Launch;
using Cybersuite.ProviderModel;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Real Wave 4 out-of-process provider connection for the managed Bouncy Castle worker.
/// The transport is a length-prefixed JSON frame protocol over redirected stdio.
///
/// The connection intentionally serializes all RPCs over a single child-process channel.
/// Cross-provider parallelism remains available at the host level; per-provider parallel
/// operations stay serialized for safety and simpler failure semantics.
/// </summary>
public sealed class BouncyCastleOutOfProcessConnection : IProviderConnection
{
    private readonly ProviderPackage _package;
    private readonly Process _process;
    private readonly Stream _stdin;
    private readonly Stream _stdout;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _stderrSync;
    private readonly StringBuilder _stderrBuffer;
    private readonly Task _stderrPump;

    private bool _shutdownRequested;
    private bool _disposed;

    private BouncyCastleOutOfProcessConnection(
        ProviderPackage package,
        Process process,
        Stream stdin,
        Stream stdout,
        object stderrSync,
        StringBuilder stderrBuffer,
        Task stderrPump)
    {
        _package = package;
        _process = process;
        _stdin = stdin;
        _stdout = stdout;
        _stderrSync = stderrSync;
        _stderrBuffer = stderrBuffer;
        _stderrPump = stderrPump;
    }

    public static ValueTask<IProviderConnection> LaunchAsync(
        ProviderPackage package,
        ProviderLaunchContext launchContext,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(launchContext);
        cancellationToken.ThrowIfCancellationRequested();
        launchContext.Validate();

        if (package.Manifest.IsolationMode != ProviderIsolationMode.OutOfProcess)
            throw new NotSupportedException("Out-of-process launch requires an OutOfProcess provider manifest.");

        ProcessStartInfo startInfo = CreateStartInfo(package, launchContext);
        var process = new Process
        {
            StartInfo = startInfo,
            EnableRaisingEvents = true
        };

        if (!process.Start())
        {
            process.Dispose();
            throw new InvalidOperationException($"Failed to start provider worker for '{package.Manifest.ProviderId.Value}'.");
        }

        var stderrSync = new object();
        var stderrBuffer = new StringBuilder();
        Task stderrPump = ConsumeStderrAsync(process.StandardError, stderrBuffer, stderrSync, CancellationToken.None);

        IProviderConnection connection = new BouncyCastleOutOfProcessConnection(
            package,
            process,
            process.StandardInput.BaseStream,
            process.StandardOutput.BaseStream,
            stderrSync,
            stderrBuffer,
            stderrPump);

        return ValueTask.FromResult(connection);
    }

    public ValueTask<ProviderHello> HandshakeAsync(ClientHello clientHello, CancellationToken cancellationToken)
        => InvokeAsync<ClientHello, ClientHelloDto, ProviderHello, ProviderHelloDto>(
            BouncyCastleWorkerProtocol.HandshakeOperation,
            clientHello,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToProviderHello,
            cancellationToken);

    public ValueTask<CapabilityResponse> GetCapabilitiesAsync(CapabilityRequest request, CancellationToken cancellationToken)
        => InvokeAsync<CapabilityRequest, CapabilityRequestDto, CapabilityResponse, CapabilityResponseDto>(
            BouncyCastleWorkerProtocol.CapabilityOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToCapabilityResponse,
            cancellationToken);

    public ValueTask<HealthResponse> HealthAsync(HealthRequest request, CancellationToken cancellationToken)
        => InvokeAsync<HealthRequest, HealthRequestDto, HealthResponse, HealthResponseDto>(
            BouncyCastleWorkerProtocol.HealthOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToHealthResponse,
            cancellationToken);

    public async ValueTask<ShutdownResponse> ShutdownAsync(ShutdownRequest request, CancellationToken cancellationToken)
    {
        ShutdownResponse response = await InvokeAsync<ShutdownRequest, ShutdownRequestDto, ShutdownResponse, ShutdownResponseDto>(
            BouncyCastleWorkerProtocol.ShutdownOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToShutdownResponse,
            cancellationToken).ConfigureAwait(false);

        _shutdownRequested = true;
        return response;
    }

    public ValueTask<KemGenerateKeyPairResponse> KemGenerateKeyPairAsync(KemGenerateKeyPairRequest request, CancellationToken cancellationToken)
        => InvokeAsync<KemGenerateKeyPairRequest, KemGenerateKeyPairRequestDto, KemGenerateKeyPairResponse, KemGenerateKeyPairResponseDto>(
            BouncyCastleWorkerProtocol.KemGenerateKeyPairOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToKemGenerateKeyPairResponse,
            cancellationToken);

    public ValueTask<KemEncapsulateResponse> KemEncapsulateAsync(KemEncapsulateRequest request, CancellationToken cancellationToken)
        => InvokeAsync<KemEncapsulateRequest, KemEncapsulateRequestDto, KemEncapsulateResponse, KemEncapsulateResponseDto>(
            BouncyCastleWorkerProtocol.KemEncapsulateOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToKemEncapsulateResponse,
            cancellationToken);

    public ValueTask<KemDecapsulateResponse> KemDecapsulateAsync(KemDecapsulateRequest request, CancellationToken cancellationToken)
        => InvokeAsync<KemDecapsulateRequest, KemDecapsulateRequestDto, KemDecapsulateResponse, KemDecapsulateResponseDto>(
            BouncyCastleWorkerProtocol.KemDecapsulateOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToKemDecapsulateResponse,
            cancellationToken);

    public ValueTask<SignatureGenerateKeyPairResponse> SignatureGenerateKeyPairAsync(SignatureGenerateKeyPairRequest request, CancellationToken cancellationToken)
        => InvokeAsync<SignatureGenerateKeyPairRequest, SignatureGenerateKeyPairRequestDto, SignatureGenerateKeyPairResponse, SignatureGenerateKeyPairResponseDto>(
            BouncyCastleWorkerProtocol.SignatureGenerateKeyPairOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToSignatureGenerateKeyPairResponse,
            cancellationToken);

    public ValueTask<SignatureSignResponse> SignatureSignAsync(SignatureSignRequest request, CancellationToken cancellationToken)
        => InvokeAsync<SignatureSignRequest, SignatureSignRequestDto, SignatureSignResponse, SignatureSignResponseDto>(
            BouncyCastleWorkerProtocol.SignatureSignOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToSignatureSignResponse,
            cancellationToken);

    public ValueTask<SignatureVerifyResponse> SignatureVerifyAsync(SignatureVerifyRequest request, CancellationToken cancellationToken)
        => InvokeAsync<SignatureVerifyRequest, SignatureVerifyRequestDto, SignatureVerifyResponse, SignatureVerifyResponseDto>(
            BouncyCastleWorkerProtocol.SignatureVerifyOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToSignatureVerifyResponse,
            cancellationToken);

    public ValueTask<AeadGenerateKeyResponse> AeadGenerateKeyAsync(AeadGenerateKeyRequest request, CancellationToken cancellationToken)
        => InvokeAsync<AeadGenerateKeyRequest, AeadGenerateKeyRequestDto, AeadGenerateKeyResponse, AeadGenerateKeyResponseDto>(
            BouncyCastleWorkerProtocol.AeadGenerateKeyOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToAeadGenerateKeyResponse,
            cancellationToken);

    public ValueTask<AeadEncryptResponse> AeadEncryptAsync(AeadEncryptRequest request, CancellationToken cancellationToken)
        => InvokeAsync<AeadEncryptRequest, AeadEncryptRequestDto, AeadEncryptResponse, AeadEncryptResponseDto>(
            BouncyCastleWorkerProtocol.AeadEncryptOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToAeadEncryptResponse,
            cancellationToken);

    public ValueTask<AeadDecryptResponse> AeadDecryptAsync(AeadDecryptRequest request, CancellationToken cancellationToken)
        => InvokeAsync<AeadDecryptRequest, AeadDecryptRequestDto, AeadDecryptResponse, AeadDecryptResponseDto>(
            BouncyCastleWorkerProtocol.AeadDecryptOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToAeadDecryptResponse,
            cancellationToken);

    public ValueTask<KdfDeriveKeyResponse> KdfDeriveKeyAsync(KdfDeriveKeyRequest request, CancellationToken cancellationToken)
        => InvokeAsync<KdfDeriveKeyRequest, KdfDeriveKeyRequestDto, KdfDeriveKeyResponse, KdfDeriveKeyResponseDto>(
            BouncyCastleWorkerProtocol.KdfDeriveKeyOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToKdfDeriveKeyResponse,
            cancellationToken);

    public ValueTask<DestroyHandleResponse> DestroyHandleAsync(DestroyHandleRequest request, CancellationToken cancellationToken)
        => InvokeAsync<DestroyHandleRequest, DestroyHandleRequestDto, DestroyHandleResponse, DestroyHandleResponseDto>(
            BouncyCastleWorkerProtocol.DestroyHandleOperation,
            request,
            BouncyCastleWorkerProtocol.ToDto,
            BouncyCastleWorkerProtocol.ToDestroyHandleResponse,
            cancellationToken);

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;

        await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try
        {
            await TryTerminateProcessAsync().ConfigureAwait(false);

            try
            {
                _stdin.Dispose();
            }
            catch
            {
                // best-effort cleanup
            }

            try
            {
                _stdout.Dispose();
            }
            catch
            {
                // best-effort cleanup
            }
        }
        finally
        {
            _gate.Release();
            _gate.Dispose();
        }

        try
        {
            await _stderrPump.ConfigureAwait(false);
        }
        catch
        {
            // stderr capture is best-effort only
        }

        _process.Dispose();
    }

    private async ValueTask<TResponse> InvokeAsync<TRequest, TRequestDto, TResponse, TResponseDto>(
        string operation,
        TRequest request,
        Func<TRequest, TRequestDto> toDto,
        Func<TResponseDto, TResponse> fromDto,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfDisposedOrExited();

            var requestFrame = new BouncyCastleWorkerFrame(
                Operation: operation,
                PayloadJson: BouncyCastleWorkerProtocol.SerializePayload(toDto(request)),
                Success: true,
                ErrorCode: null,
                ErrorMessage: null);

            await BouncyCastleWorkerProtocol.WriteFrameAsync(_stdin, requestFrame, cancellationToken).ConfigureAwait(false);
            BouncyCastleWorkerFrame responseFrame = await BouncyCastleWorkerProtocol.ReadFrameAsync(_stdout, cancellationToken).ConfigureAwait(false);

            ThrowIfDisposedOrExited();

            if (!string.Equals(responseFrame.Operation, operation, StringComparison.Ordinal))
                throw new OopProtocolException($"Worker response operation mismatch. Expected '{operation}', got '{responseFrame.Operation}'.");

            if (!responseFrame.Success)
                throw CreateWorkerException(operation, responseFrame.ErrorCode, responseFrame.ErrorMessage);

            TResponseDto responseDto = BouncyCastleWorkerProtocol.DeserializePayload<TResponseDto>(responseFrame.PayloadJson);
            return fromDto(responseDto);
        }
        catch (EndOfStreamException ex)
        {
            throw new OopProtocolException(BuildWorkerFailureMessage($"Worker channel closed unexpectedly during '{operation}'.", ex));
        }
        catch (IOException ex)
        {
            throw new OopProtocolException(BuildWorkerFailureMessage($"Worker I/O failed during '{operation}'.", ex));
        }
        finally
        {
            _gate.Release();
        }
    }

    private static ProcessStartInfo CreateStartInfo(ProviderPackage package, ProviderLaunchContext launchContext)
    {
        ProcessStartInfo startInfo;
        string extension = Path.GetExtension(package.EntrypointPath);
        if (string.Equals(extension, ".dll", StringComparison.OrdinalIgnoreCase))
        {
            startInfo = new ProcessStartInfo("dotnet")
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = package.PackageRoot,
                StandardErrorEncoding = Encoding.UTF8,
                StandardOutputEncoding = Encoding.UTF8
            };

            startInfo.ArgumentList.Add(package.EntrypointPath);
        }
        else
        {
            startInfo = new ProcessStartInfo(package.EntrypointPath)
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = package.PackageRoot,
                StandardErrorEncoding = Encoding.UTF8,
                StandardOutputEncoding = Encoding.UTF8
            };
        }

        byte[] bootstrapBytes = JsonSerializer.SerializeToUtf8Bytes(
            BouncyCastleWorkerProtocol.ToBootstrapDto(package),
            BouncyCastleWorkerProtocol.JsonOptions);
        try
        {
            startInfo.Environment[BouncyCastleWorkerProtocol.BootstrapEnvironmentVariableName] = Convert.ToBase64String(bootstrapBytes);
            startInfo.Environment["CYBERSUITE_PROVIDER_ENABLE_NETWORK_ACCESS"] = launchContext.EnableNetworkAccess ? "1" : "0";
            startInfo.Environment["CYBERSUITE_PROVIDER_PROFILE"] = launchContext.Profile.ToString();
        }
        finally
        {
            Array.Clear(bootstrapBytes, 0, bootstrapBytes.Length);
        }

        return startInfo;
    }

    private async Task TryTerminateProcessAsync()
    {
        if (_process.HasExited)
            return;

        try
        {
            if (_shutdownRequested)
            {
                using var waitCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _process.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
                return;
            }
        }
        catch
        {
            // Fall through to kill below.
        }

        try
        {
            _process.Kill(entireProcessTree: true);
        }
        catch
        {
            // best-effort cleanup
        }

        try
        {
            using var waitCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await _process.WaitForExitAsync(waitCts.Token).ConfigureAwait(false);
        }
        catch
        {
            // best-effort cleanup
        }
    }

    private static async Task ConsumeStderrAsync(StreamReader stderr, StringBuilder buffer, object sync, CancellationToken cancellationToken)
    {
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string? line = await stderr.ReadLineAsync().ConfigureAwait(false);
                if (line is null)
                    break;

                lock (sync)
                {
                    if (buffer.Length > 4096)
                        buffer.Remove(0, Math.Min(1024, buffer.Length));

                    if (buffer.Length > 0)
                        buffer.Append(" | ");

                    if (line.Length > 512)
                        line = line[..512];

                    buffer.Append(line);
                }
            }
        }
        catch
        {
            // best-effort capture is optional
        }
    }

    private void ThrowIfDisposedOrExited()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (_process.HasExited)
        {
            throw new OopProtocolException(
                BuildWorkerFailureMessage(
                    $"Provider worker for '{_package.Manifest.ProviderId.Value}' has exited with code {_process.ExitCode}.",
                    exception: null));
        }
    }

    private OopProtocolException CreateWorkerException(string operation, string? errorCode, string? errorMessage)
    {
        string message = $"Worker operation '{operation}' failed";
        if (!string.IsNullOrWhiteSpace(errorCode))
            message += $" [{errorCode}]";
        if (!string.IsNullOrWhiteSpace(errorMessage))
            message += $": {errorMessage}";

        return new OopProtocolException(BuildWorkerFailureMessage(message, exception: null));
    }

    private string BuildWorkerFailureMessage(string message, Exception? exception)
    {
        string stderrTail = ReadStderrTail();
        if (string.IsNullOrWhiteSpace(stderrTail))
            return exception is null ? message : $"{message} {exception.Message}";

        return exception is null
            ? $"{message} Worker stderr tail: {stderrTail}"
            : $"{message} {exception.Message} Worker stderr tail: {stderrTail}";
    }

    private string ReadStderrTail()
    {
        lock (_stderrSync)
        {
            return _stderrBuffer.ToString();
        }
    }
}

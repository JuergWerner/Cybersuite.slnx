using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Text;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.OopProtocol;

/// <summary>
/// Deterministic canonical binary encoding for hashing and binding.
/// Transport may later use protobuf/gRPC; hashing MUST use this canonical encoding.
/// </summary>
internal static class OopWireFormat
{
    public static byte[] EncodeClientHello(Handshake.ClientHello msg)
    {
        var buffer = new ArrayBufferWriter<byte>(256);

        WriteU16(buffer, (ushort)OopMessageType.ClientHello);
        WriteU16(buffer, msg.Version.Major);
        WriteU16(buffer, msg.Version.Minor);

        WriteFixed(buffer, msg.Nonce.Span, OopConstants.NonceSizeBytes);
        WriteFixed(buffer, msg.PolicyHashSha384.Span, OopConstants.Sha384SizeBytes);

        WriteU8(buffer, (byte)msg.Profile);

        byte flags = 0;
        if (msg.FipsRequired) flags |= 0b0000_0001;
        if (msg.ExperimentalAllowed) flags |= 0b0000_0010;
        WriteU8(buffer, flags);

        WriteOptString(buffer, msg.TenantId);
        WriteOptString(buffer, msg.ExpectedProviderId);
        WriteOptString(buffer, msg.ExpectedBuildHash);

        return buffer.WrittenSpan.ToArray();
    }

    public static byte[] EncodeProviderHello(Handshake.ProviderHello msg)
    {
        var buffer = new ArrayBufferWriter<byte>(512);

        WriteU16(buffer, (ushort)OopMessageType.ProviderHello);
        WriteU16(buffer, msg.Version.Major);
        WriteU16(buffer, msg.Version.Minor);

        WriteFixed(buffer, msg.Nonce.Span, OopConstants.NonceSizeBytes);

        WriteString(buffer, msg.Identity.ProviderId.Value);
        WriteString(buffer, msg.Identity.Version);
        WriteString(buffer, msg.Identity.BuildHash);
        WriteOptString(buffer, msg.Identity.SignatureFingerprint);

        WriteFixed(buffer, msg.CapabilityHashSha384.Span, OopConstants.Sha384SizeBytes);
        WriteComplianceEnvelope(buffer, msg.ComplianceEnvelope);

        byte flags = 0;
        if (msg.FipsBoundaryDeclared) flags |= 0b0000_0001;
        if (msg.IsExperimental) flags |= 0b0000_0010;
        WriteU8(buffer, flags);

        WriteOptBytes(buffer, msg.AttestationEvidence);

        return buffer.WrittenSpan.ToArray();
    }

    public static byte[] EncodeRequestHeader(Headers.OopRequestHeader header)
    {
        var buffer = new ArrayBufferWriter<byte>(128);

        WriteU16(buffer, (ushort)header.MessageType);
        WriteU16(buffer, header.Version.Major);
        WriteU16(buffer, header.Version.Minor);

        Span<byte> req = stackalloc byte[OopConstants.HandleSizeBytes];
        header.RequestId.WriteBytes(req);
        WriteFixed(buffer, req, OopConstants.HandleSizeBytes);

        WriteU64(buffer, header.MessageCounter);
        WriteFixed(buffer, header.ChannelBindingSha384.Span, OopConstants.Sha384SizeBytes);

        return buffer.WrittenSpan.ToArray();
    }

    public static byte[] EncodeResponseHeader(Headers.OopResponseHeader header)
    {
        var buffer = new ArrayBufferWriter<byte>(160);

        WriteU16(buffer, (ushort)header.MessageType);
        WriteU16(buffer, header.Version.Major);
        WriteU16(buffer, header.Version.Minor);

        Span<byte> req = stackalloc byte[OopConstants.HandleSizeBytes];
        header.RequestId.WriteBytes(req);
        WriteFixed(buffer, req, OopConstants.HandleSizeBytes);

        WriteU64(buffer, header.MessageCounter);
        WriteFixed(buffer, header.ChannelBindingSha384.Span, OopConstants.Sha384SizeBytes);

        WriteU8(buffer, header.Success ? (byte)1 : (byte)0);

        if (header.Error is null)
        {
            WriteU8(buffer, 0);
        }
        else
        {
            WriteU8(buffer, 1);
            WriteU16(buffer, (ushort)header.Error.Code);
            WriteString(buffer, header.Error.Message);
        }

        return buffer.WrittenSpan.ToArray();
    }

    private static void WriteComplianceEnvelope(IBufferWriter<byte> w, ProviderComplianceEnvelope envelope)
    {
        WriteU8(w, (byte)envelope.SecurityClass);
        WriteU8(w, (byte)envelope.BoundaryClass);
        WriteU8(w, envelope.DeclaredValidatedBoundary ? (byte)1 : (byte)0);
        WriteOptString(w, envelope.DeclaredModuleName);
        WriteOptString(w, envelope.DeclaredCertificateReference);
        WriteOptString(w, envelope.DeclaredModuleVersion);
        WriteU8(w, envelope.SupportsNonExportableKeys ? (byte)1 : (byte)0);
        WriteU8(w, envelope.SupportsRawSecretEgress ? (byte)1 : (byte)0);
        WriteU8(w, (byte)envelope.AttestationMode);
        WriteFixed(w, envelope.EnvelopeHashSha384.AsSpan(), OopConstants.Sha384SizeBytes);
    }

    // ---- Primitive writers (network order / deterministic) ----

    private static void WriteU8(IBufferWriter<byte> w, byte v)
    {
        Span<byte> s = w.GetSpan(1);
        s[0] = v;
        w.Advance(1);
    }

    private static void WriteU16(IBufferWriter<byte> w, ushort v)
    {
        Span<byte> s = w.GetSpan(2);
        BinaryPrimitives.WriteUInt16BigEndian(s, v);
        w.Advance(2);
    }

    private static void WriteU32(IBufferWriter<byte> w, uint v)
    {
        Span<byte> s = w.GetSpan(4);
        BinaryPrimitives.WriteUInt32BigEndian(s, v);
        w.Advance(4);
    }

    private static void WriteU64(IBufferWriter<byte> w, ulong v)
    {
        Span<byte> s = w.GetSpan(8);
        BinaryPrimitives.WriteUInt64BigEndian(s, v);
        w.Advance(8);
    }

    private static void WriteFixed(IBufferWriter<byte> w, ReadOnlySpan<byte> bytes, int requiredLen)
    {
        if (bytes.Length != requiredLen)
            throw new OopProtocolException($"Fixed field length mismatch. Expected {requiredLen} bytes.");

        Span<byte> s = w.GetSpan(requiredLen);
        bytes.CopyTo(s);
        w.Advance(requiredLen);
    }

    private static void WriteString(IBufferWriter<byte> w, string value)
    {
        value ??= string.Empty;
        value = value.Normalize(NormalizationForm.FormC);

        int byteCount = Encoding.UTF8.GetByteCount(value);
        WriteU32(w, (uint)byteCount);

        Span<byte> s = w.GetSpan(byteCount);
        Encoding.UTF8.GetBytes(value, s);
        w.Advance(byteCount);
    }

    private static void WriteOptString(IBufferWriter<byte> w, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            WriteU8(w, 0);
            return;
        }

        WriteU8(w, 1);
        WriteString(w, value);
    }

    private static void WriteOptBytes(IBufferWriter<byte> w, ReadOnlyMemory<byte>? bytes)
    {
        if (bytes is null || bytes.Value.IsEmpty)
        {
            WriteU8(w, 0);
            return;
        }

        WriteU8(w, 1);
        var span = bytes.Value.Span;
        WriteU32(w, (uint)span.Length);

        Span<byte> s = w.GetSpan(span.Length);
        span.CopyTo(s);
        w.Advance(span.Length);
    }
}

using System;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Cybersuite.Abstractions;
using Cybersuite.OopProtocol.Handshake;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Verifies structured self-attestation evidence carried in <see cref="ProviderHello"/>.
/// The verifier is intentionally honest about its strength: it validates fresh, structured evidence
/// and can pin the evidence hash, but it does not claim hardware-backed remote attestation.
/// </summary>
public sealed class StructuredAttestationVerifier : IProviderAttestationVerifier
{
    public static StructuredAttestationVerifier Default { get; } = new();

    public ValueTask<ProviderAttestationVerificationResult> VerifyAsync(
        ProviderPackage package,
        ProviderHello providerHello,
        ProviderSessionBinding binding,
        ProviderHostOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(package);
        ArgumentNullException.ThrowIfNull(providerHello);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(options);

        AttestationRequirement requirement = binding.EffectiveCompliance?.AttestationRequirement ?? AttestationRequirement.None;
        bool evidenceRequired = requirement == AttestationRequirement.Required ||
            (options.ExecutionProfile != ExecutionProfile.Dev &&
             options.RequireAttestationInNonDevWhenDeclared &&
             providerHello.ComplianceEnvelope.AttestationMode != AttestationMode.None);

        ReadOnlyMemory<byte>? evidence = providerHello.AttestationEvidence;
        if (evidence is null || evidence.Value.IsEmpty)
        {
            return ValueTask.FromResult(
                evidenceRequired
                    ? ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Missing,
                        "Attestation evidence is required but missing.")
                    : ProviderAttestationVerificationResult.Accepted(
                        ProviderAttestationStatus.NotRequired,
                        "Attestation evidence not required in the current context."));
        }

        byte[] evidenceBytes = evidence.Value.ToArray();
        try
        {
            string evidenceSha256Hex = Convert.ToHexString(SHA256.HashData(evidenceBytes));

            if (!ProviderStructuredAttestationStatement.TryParse(evidenceBytes, out ProviderStructuredAttestationStatement? statement, out string? parseFailure))
            {
                return ValueTask.FromResult(
                    ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Rejected,
                        parseFailure ?? "Attestation statement parsing failed.",
                        evidenceSha256Hex));
            }

            if (!string.Equals(statement!.ProviderId, providerHello.Identity.ProviderId.Value, StringComparison.Ordinal) ||
                !string.Equals(statement.ProviderId, package.Manifest.ProviderId.Value, StringComparison.Ordinal))
            {
                return ValueTask.FromResult(
                    ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Rejected,
                        "Attestation statement provider id mismatch.",
                        evidenceSha256Hex));
            }

            if (!string.Equals(statement.BuildHashSha256Hex, providerHello.Identity.BuildHash, StringComparison.OrdinalIgnoreCase))
            {
                return ValueTask.FromResult(
                    ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Rejected,
                        "Attestation statement build hash mismatch.",
                        evidenceSha256Hex));
            }

            if (statement.SecurityClass != providerHello.ComplianceEnvelope.SecurityClass ||
                statement.BoundaryClass != providerHello.ComplianceEnvelope.BoundaryClass)
            {
                return ValueTask.FromResult(
                    ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Rejected,
                        "Attestation statement boundary claim mismatch.",
                        evidenceSha256Hex));
            }

            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (statement.IssuedAtUtc > now + TimeSpan.FromMinutes(1))
            {
                return ValueTask.FromResult(
                    ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Rejected,
                        "Attestation statement issue time is in the future.",
                        evidenceSha256Hex));
            }

            if (now - statement.IssuedAtUtc > options.MaxStructuredAttestationAge)
            {
                return ValueTask.FromResult(
                    ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Rejected,
                        "Attestation statement is too old.",
                        evidenceSha256Hex));
            }

            if (options.ExpectedAttestationEvidenceSha256ByProvider.TryGetValue(providerHello.Identity.ProviderId, out ImmutableArray<byte> expectedHash) &&
                (!TryParseHex(evidenceSha256Hex, out byte[] actualHash) || !FixedTimeEqualsAndZero(actualHash, expectedHash)))
            {
                return ValueTask.FromResult(
                    ProviderAttestationVerificationResult.Rejected(
                        ProviderAttestationStatus.Rejected,
                        "Attestation evidence hash mismatch.",
                        evidenceSha256Hex));
            }

            ProviderAttestationStatus status = requirement == AttestationRequirement.Required
                ? ProviderAttestationStatus.Verified
                : ProviderAttestationStatus.Presented;

            return ValueTask.FromResult(
                ProviderAttestationVerificationResult.Accepted(
                    status,
                    "Structured attestation evidence accepted.",
                    evidenceSha256Hex));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(evidenceBytes);
        }
    }

    private static bool TryParseHex(string hex, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(hex))
            return false;

        string normalized = hex.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[2..];

        if ((normalized.Length % 2) != 0)
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

    private static bool FixedTimeEqualsAndZero(byte[] actualHash, ImmutableArray<byte> expectedHash)
    {
        try
        {
            if (expectedHash.IsDefaultOrEmpty || expectedHash.Length != actualHash.Length)
                return false;

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash.AsSpan());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(actualHash);
        }
    }
}

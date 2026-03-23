using System;
using System.Text.Json;
using Cybersuite.Abstractions;
using Cybersuite.ProviderModel;

namespace Cybersuite.ProviderHost.Trust;

/// <summary>
/// Structured self-attestation statement encoded into <see cref="Cybersuite.OopProtocol.Handshake.ProviderHello.AttestationEvidence"/>.
/// Wave 4 deliberately treats this as self-declared evidence unless an allowlisted hash binds it further.
/// </summary>
public sealed record ProviderStructuredAttestationStatement(
    string ProviderId,
    string BuildHashSha256Hex,
    ProviderSecurityClass SecurityClass,
    RequiredBoundaryClass BoundaryClass,
    string? ModuleName,
    string? ModuleVersion,
    DateTimeOffset IssuedAtUtc)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true
    };

    public byte[] ToUtf8Bytes()
        => JsonSerializer.SerializeToUtf8Bytes(this, JsonOptions);

    public static bool TryParse(ReadOnlySpan<byte> utf8, out ProviderStructuredAttestationStatement? statement, out string? failureReason)
    {
        statement = null;
        failureReason = null;

        if (utf8.IsEmpty)
        {
            failureReason = "Attestation statement is empty.";
            return false;
        }

        try
        {
            statement = JsonSerializer.Deserialize<ProviderStructuredAttestationStatement>(utf8, JsonOptions);
            if (statement is null)
            {
                failureReason = "Attestation statement could not be deserialized.";
                return false;
            }

            if (string.IsNullOrWhiteSpace(statement.ProviderId))
            {
                failureReason = "Attestation statement provider id is missing.";
                statement = null;
                return false;
            }

            if (string.IsNullOrWhiteSpace(statement.BuildHashSha256Hex))
            {
                failureReason = "Attestation statement build hash is missing.";
                statement = null;
                return false;
            }

            return true;
        }
        catch (JsonException)
        {
            failureReason = "Attestation statement is not valid JSON.";
            return false;
        }
    }
}

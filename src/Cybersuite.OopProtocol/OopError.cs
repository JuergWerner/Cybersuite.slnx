using System;

namespace Cybersuite.OopProtocol;

/// <summary>
/// Structured error payload for OPP responses. Carried inside <see cref="Headers.OopResponseHeader"/>
/// when a request cannot be fulfilled.
///
/// <b>Security invariant:</b> error messages MUST NOT include secrets, raw key material,
/// or internal stack traces. Messages are kept generic and non-sensitive to prevent
/// information leakage across the provider trust boundary.
/// </summary>
public sealed class OopError
{
    /// <summary>Structured error code identifying the error category (see <see cref="OopErrorCode"/>).</summary>
    public OopErrorCode Code { get; }

    /// <summary>Human-readable, non-sensitive error message. Defaults to "error" if empty.</summary>
    public string Message { get; }

    public OopError(OopErrorCode code, string message)
    {
        Code = code;
        Message = string.IsNullOrWhiteSpace(message) ? "error" : message;
    }

    public override string ToString() => $"{Code}: {Message}";
}
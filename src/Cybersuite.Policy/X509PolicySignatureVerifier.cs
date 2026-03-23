using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Cybersuite.Policy;

/// <summary>
/// Minimal X.509 based signature verifier for policy canonical bytes.
/// FIPS-awareness: uses SHA-384 and RSA-PSS or ECDSA P-384.
/// </summary>
public sealed class X509PolicySignatureVerifier : IPolicySignatureVerifier
{
    public bool Verify(
        ReadOnlySpan<byte> canonicalPolicyBytes,
        PolicySignatureEnvelope signature,
        PolicySignatureVerificationOptions options,
        out string? failureReason)
    {
        failureReason = null;

        try
        {
            using var signerCert = X509CertificateLoader.LoadCertificate(signature.SignerCertificateDer.Span);

            // SEC-M-006: Explicit certificate expiry check.
            // The chain build checks this implicitly, but in Dev-mode chain failures are tolerated
            // (AllowUntrustedChainInDevOnly). This explicit guard ensures expired certificates are
            // always rejected, regardless of chain policy or profile.
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (now < signerCert.NotBefore)
                return Fail("Signer certificate is not yet valid (NotBefore).", out failureReason);
            if (now > signerCert.NotAfter)
                return Fail("Signer certificate has expired (NotAfter).", out failureReason);

            if (options.AllowedSignerThumbprints.Count > 0)
            {
                var thumbprint = (signerCert.Thumbprint ?? string.Empty).Replace(" ", string.Empty).ToUpperInvariant();
                if (!options.AllowedSignerThumbprints.Contains(thumbprint))
                {
                    failureReason = "Signer certificate thumbprint not allowlisted.";
                    return false;
                }
            }

            // Chain validation (prefer custom roots if provided)
            using var chain = new X509Chain();
            // SEC-M-001: Use configurable revocation mode (default: NoCheck; recommended for Prod: Online)
            chain.ChainPolicy.RevocationMode = options.RevocationMode;

            if (!options.TrustedRootsDer.IsDefaultOrEmpty && options.TrustedRootsDer.Length > 0)
            {
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                foreach (var rootDer in options.TrustedRootsDer)
                {
                    using var root = X509CertificateLoader.LoadCertificate(rootDer.Span);
                    chain.ChainPolicy.CustomTrustStore.Add(root);
                }
            }

            // Add intermediates (best-effort)
            for (int i = 0; i < signature.AdditionalCertificatesDer.Length; i++)
            {
                using var intermediate = X509CertificateLoader.LoadCertificate(signature.AdditionalCertificatesDer[i].Span);
                chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            bool chainOk = chain.Build(signerCert);
            if (!chainOk && !options.AllowUntrustedChainInDevOnly)
            {
                failureReason = "Certificate chain validation failed.";
                return false;
            }

            // Verify signature on canonical bytes
            return signature.Algorithm switch
            {
                PolicySignatureAlgorithm.RsaPssSha384 => VerifyRsaPssSha384(signerCert, canonicalPolicyBytes, signature.SignatureBytes.Span, out failureReason),
                PolicySignatureAlgorithm.EcdsaP384Sha384 => VerifyEcdsaP384Sha384(signerCert, canonicalPolicyBytes, signature.SignatureBytes.Span, out failureReason),
                _ => Fail("Unsupported signature algorithm.", out failureReason)
            };
        }
        catch (Exception)
        {
            // SEC-L-002: Generic error message to avoid leaking internal type information.
            failureReason = "Signature verification failed due to an internal error.";
            return false;
        }
    }

    private static bool VerifyRsaPssSha384(X509Certificate2 cert, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, out string? reason)
    {
        reason = null;
        using RSA? rsa = cert.GetRSAPublicKey();
        if (rsa is null)
        {
            reason = "Signer certificate has no RSA public key.";
            return false;
        }

        bool ok = rsa.VerifyData(data, sig, HashAlgorithmName.SHA384, RSASignaturePadding.Pss);
        if (!ok) reason = "RSA-PSS-SHA384 signature invalid.";
        return ok;
    }

    private static bool VerifyEcdsaP384Sha384(X509Certificate2 cert, ReadOnlySpan<byte> data, ReadOnlySpan<byte> sig, out string? reason)
    {
        reason = null;
        using ECDsa? ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa is null)
        {
            reason = "Signer certificate has no ECDSA public key.";
            return false;
        }

        bool ok = ecdsa.VerifyData(data, sig, HashAlgorithmName.SHA384);
        if (!ok) reason = "ECDSA-SHA384 signature invalid.";
        return ok;
    }

    private static bool Fail(string msg, out string? reason)
    {
        reason = msg;
        return false;
    }
}
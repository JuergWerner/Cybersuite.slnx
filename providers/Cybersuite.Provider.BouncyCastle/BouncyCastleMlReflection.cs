using System;
using System.Collections.Generic;
using System.Reflection;
using System.Security.Cryptography;
using Org.BouncyCastle.Security;
using Cybersuite.Abstractions;

namespace Cybersuite.Provider.BouncyCastle;

/// <summary>
/// Reflection-based ML-KEM / ML-DSA binding to keep compile-time stability
/// across BC package changes while still allowing operational use when the expected
/// PQC classes are present in the installed package.
///
/// This is intentionally fail-closed: if required BC PQC types or members are absent,
/// a NotSupportedException is thrown.
/// </summary>
internal static class BouncyCastleMlReflection
{
    private static Assembly BcAssembly => typeof(SecureRandom).Assembly;

    public static KemKeyPair GenerateMlKemKeyPair(
        ProviderId providerId,
        AlgorithmId algorithmId,
        AlgorithmParameterSetId parameterSetId,
        BouncyCastleKeyMaterialStore store,
        SecureRandom random)
    {
        object parameters = ResolveMlKemParameters(parameterSetId.Value);
        Type publicKeyType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Parameters.MLKemPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemPublicKeyParameters");
        Type privateKeyType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Parameters.MLKemPrivateKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMPrivateKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemPrivateKeyParameters");

        object keyPair = GeneratePqcKeyPair(
            parameters,
            random,
            new[]
            {
                "Org.BouncyCastle.Crypto.Generators.MLKemKeyPairGenerator",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMKeyPairGenerator",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemKeyPairGenerator"
            },
            new[]
            {
                "Org.BouncyCastle.Crypto.Parameters.MLKemKeyGenerationParameters",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMKeyGenerationParameters",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemKeyGenerationParameters"
            });

        object publicObj = GetRequiredMemberValue(keyPair, "Public");
        object privateObj = GetRequiredMemberValue(keyPair, "Private");

        if (!publicKeyType.IsInstanceOfType(publicObj))
            throw new NotSupportedException("BC ML-KEM public key type mismatch.");

        if (!privateKeyType.IsInstanceOfType(privateObj))
            throw new NotSupportedException("BC ML-KEM private key type mismatch.");

        byte[] publicBytes = GetEncoded(publicObj);
        PrivateKeyHandle privateHandle = store.AddPrivateKeyObject(providerId, privateObj);

        return new KemKeyPair(new PublicKey(algorithmId, publicBytes), privateHandle);
    }

    public static KemEncapsulationResult EncapsulateMlKem(
        ProviderId providerId,
        AlgorithmId algorithmId,
        AlgorithmParameterSetId parameterSetId,
        in PublicKey recipientPublicKey,
        BouncyCastleKeyMaterialStore store,
        SecureRandom random)
    {
        object parameters = ResolveMlKemParameters(parameterSetId.Value);
        Type publicKeyType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Parameters.MLKemPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemPublicKeyParameters");

        object recipientKey = CreateKeyParameterFromEncoding(
            publicKeyType,
            parameters,
            recipientPublicKey.Bytes.Span);

        byte[] secret;
        byte[] ciphertext;

        // Try BC 2.7+ IKemEncapsulator API first
        Type? encapsulatorType = BcAssembly.GetType("Org.BouncyCastle.Crypto.Kems.MLKemEncapsulator", throwOnError: false);
        if (encapsulatorType is not null)
        {
            // BC 2.7: public ctor(MLKemParameters); BC 2.6: internal ctor
            object encapsulator = CreatePqcInstance(encapsulatorType, parameters);
            InvokeRequiredVoidMethod(encapsulator, "Init", recipientKey);

            int encLen = (int)GetRequiredMemberValue(encapsulator, "EncapsulationLength");
            int secLen = (int)GetRequiredMemberValue(encapsulator, "SecretLength");
            ciphertext = new byte[encLen];
            secret = new byte[secLen];
            InvokeRequiredVoidMethod(encapsulator, "Encapsulate", ciphertext, 0, encLen, secret, 0, secLen);
        }
        else
        {
            // Fallback: legacy BC PQC Generator API
            Type generatorType = ResolveRequiredType(
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMGenerator",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemGenerator");
            object generator = Activator.CreateInstance(generatorType, random)
                ?? throw new NotSupportedException("Unable to create BC ML-KEM generator.");
            object secretWithEncapsulation = InvokeRequiredMethod(generator, "GenerateEncapsulated", recipientKey);
            secret = GetBytesFromRequiredMethod(secretWithEncapsulation, "GetSecret");
            ciphertext = GetBytesFromRequiredMethod(secretWithEncapsulation, "GetEncapsulation");
        }

        try
        {
            SharedSecretHandle sharedSecretHandle = store.AddSharedSecret(providerId, secret);
            return new KemEncapsulationResult(ciphertext, sharedSecretHandle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public static SharedSecretHandle DecapsulateMlKem(
        ProviderId providerId,
        AlgorithmParameterSetId parameterSetId,
        PrivateKeyHandle privateKeyHandle,
        ReadOnlySpan<byte> ciphertext,
        BouncyCastleKeyMaterialStore store)
    {
        object privateKey = store.GetPrivateKeyObject(privateKeyHandle);
        byte[] ciphertextCopy = ciphertext.ToArray();
        byte[] secret;

        // Try BC 2.7+ IKemDecapsulator API first
        Type? decapsulatorType = BcAssembly.GetType("Org.BouncyCastle.Crypto.Kems.MLKemDecapsulator", throwOnError: false);
        if (decapsulatorType is not null)
        {
            try
            {
                object parameters = ResolveMlKemParameters(parameterSetId.Value);
                // BC 2.7: public ctor(MLKemParameters); BC 2.6: internal ctor
                object decapsulator = CreatePqcInstance(decapsulatorType, parameters);
                InvokeRequiredVoidMethod(decapsulator, "Init", privateKey);

                int secLen = (int)GetRequiredMemberValue(decapsulator, "SecretLength");
                secret = new byte[secLen];
                InvokeRequiredVoidMethod(decapsulator, "Decapsulate", ciphertextCopy, 0, ciphertextCopy.Length, secret, 0, secLen);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertextCopy);
            }
        }
        else
        {
            // Fallback: legacy BC PQC Extractor API
            Type extractorType = ResolveRequiredType(
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMExtractor",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemExtractor");
            object extractor = Activator.CreateInstance(extractorType, privateKey)
                ?? throw new NotSupportedException("Unable to create BC ML-KEM extractor.");
            try
            {
                object result = InvokeRequiredMethod(extractor, "ExtractSecret", ciphertextCopy);
                if (result is not byte[] secretBytes)
                    throw new NotSupportedException("BC ML-KEM extractor did not return byte[].");
                secret = secretBytes;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(ciphertextCopy);
            }
        }

        try
        {
            return store.AddSharedSecret(providerId, secret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(secret);
        }
    }

    public static SignatureKeyPair GenerateMlDsaKeyPair(
        ProviderId providerId,
        AlgorithmId algorithmId,
        AlgorithmParameterSetId parameterSetId,
        BouncyCastleKeyMaterialStore store,
        SecureRandom random)
    {
        object parameters = ResolveMlDsaParameters(parameterSetId.Value);
        Type publicKeyType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Parameters.MLDsaPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaPublicKeyParameters");
        Type privateKeyType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Parameters.MLDsaPrivateKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumPrivateKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaPrivateKeyParameters");

        object keyPair = GeneratePqcKeyPair(
            parameters,
            random,
            new[]
            {
                "Org.BouncyCastle.Crypto.Generators.MLDsaKeyPairGenerator",
                "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyPairGenerator",
                "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaKeyPairGenerator"
            },
            new[]
            {
                "Org.BouncyCastle.Crypto.Parameters.MLDsaKeyGenerationParameters",
                "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumKeyGenerationParameters",
                "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaKeyGenerationParameters"
            });

        object publicObj = GetRequiredMemberValue(keyPair, "Public");
        object privateObj = GetRequiredMemberValue(keyPair, "Private");

        if (!publicKeyType.IsInstanceOfType(publicObj))
            throw new NotSupportedException("BC ML-DSA public key type mismatch.");

        if (!privateKeyType.IsInstanceOfType(privateObj))
            throw new NotSupportedException("BC ML-DSA private key type mismatch.");

        byte[] publicBytes = GetEncoded(publicObj);
        PrivateKeyHandle privateHandle = store.AddPrivateKeyObject(providerId, privateObj);

        return new SignatureKeyPair(new PublicKey(algorithmId, publicBytes), privateHandle);
    }

    public static byte[] SignMlDsa(
        AlgorithmParameterSetId parameterSetId,
        PrivateKeyHandle privateKeyHandle,
        ReadOnlySpan<byte> message,
        BouncyCastleKeyMaterialStore store)
    {
        object privateKey = store.GetPrivateKeyObject(privateKeyHandle);
        object parameters = ResolveMlDsaParameters(parameterSetId.Value);
        Type signerType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Signers.MLDsaSigner",
            "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumSigner",
            "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaSigner");

        // BC 2.7: MLDsaSigner(MLDsaParameters, bool deterministic)
        // Older:  DilithiumSigner() parameterless
        object signer = CreatePqcInstance(signerType, parameters, true);

        InvokeRequiredVoidMethod(signer, "Init", true, privateKey);

        byte[] messageCopy = message.ToArray();
        try
        {
            FeedSignerMessage(signer, messageCopy);
            return GetBytesFromRequiredMethod(signer, "GenerateSignature");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageCopy);
        }
    }

    public static bool VerifyMlDsa(
        AlgorithmParameterSetId parameterSetId,
        in PublicKey publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        object parameters = ResolveMlDsaParameters(parameterSetId.Value);
        Type publicKeyType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Parameters.MLDsaPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumPublicKeyParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaPublicKeyParameters");

        object publicKeyObj = CreateKeyParameterFromEncoding(
            publicKeyType,
            parameters,
            publicKey.Bytes.Span);

        Type signerType = ResolveRequiredType(
            "Org.BouncyCastle.Crypto.Signers.MLDsaSigner",
            "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumSigner",
            "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaSigner");

        // BC 2.7: MLDsaSigner(MLDsaParameters, bool deterministic)
        // Older:  DilithiumSigner() parameterless
        object signer = CreatePqcInstance(signerType, parameters, true);

        InvokeRequiredVoidMethod(signer, "Init", false, publicKeyObj);

        byte[] messageCopy = message.ToArray();
        byte[] signatureCopy = signature.ToArray();

        try
        {
            FeedSignerMessage(signer, messageCopy);
            object result = InvokeRequiredMethod(signer, "VerifySignature", signatureCopy);
            return result is bool b && b;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(messageCopy);
            CryptographicOperations.ZeroMemory(signatureCopy);
        }
    }

    private static object ResolveMlKemParameters(string parameterSetId)
        => ResolveParametersObject(
            new[]
            {
                "Org.BouncyCastle.Crypto.Parameters.MLKemParameters",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKEMParameters",
                "Org.BouncyCastle.Pqc.Crypto.MLKem.MLKemParameters"
            },
            parameterSetId);

    private static object ResolveMlDsaParameters(string parameterSetId)
    {
        // BC 2.7: MLDsaParameters with ml_dsa_44/65/87
        // BC 2.6: DilithiumParameters with Dilithium2/3/5
        string[] paramTypeCandidates = new[]
        {
            "Org.BouncyCastle.Crypto.Parameters.MLDsaParameters",
            "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium.DilithiumParameters",
            "Org.BouncyCastle.Pqc.Crypto.MLDsa.MLDsaParameters"
        };

        Type parametersType = ResolveRequiredType(paramTypeCandidates);
        string target = NormalizeIdentifier(parameterSetId);

        // Also try Dilithium mapping: ML-DSA-44→Dilithium2, ML-DSA-65→Dilithium3, ML-DSA-87→Dilithium5
        string[] alternateNames = target switch
        {
            "mldsa44" => new[] { "mldsa44", "dilithium2" },
            "mldsa65" => new[] { "mldsa65", "dilithium3" },
            "mldsa87" => new[] { "mldsa87", "dilithium5" },
            _ => new[] { target }
        };

        foreach (FieldInfo f in parametersType.GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            string normalized = NormalizeIdentifier(f.Name);
            foreach (string alt in alternateNames)
            {
                if (normalized == alt)
                {
                    object? v = f.GetValue(null);
                    if (v is not null)
                        return v;
                }
            }
        }

        throw new NotSupportedException($"BC parameter set '{parameterSetId}' not found in type '{parametersType.FullName}'.");
    }

    private static object ResolveParametersObject(string[] typeCandidates, string parameterSetId)
    {
        Type parametersType = ResolveRequiredType(typeCandidates);
        string target = NormalizeIdentifier(parameterSetId);

        foreach (FieldInfo f in parametersType.GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            if (NormalizeIdentifier(f.Name) == target)
            {
                object? v = f.GetValue(null);
                if (v is not null)
                    return v;
            }
        }

        foreach (PropertyInfo p in parametersType.GetProperties(BindingFlags.Public | BindingFlags.Static))
        {
            if (NormalizeIdentifier(p.Name) == target)
            {
                object? v = p.GetValue(null);
                if (v is not null)
                    return v;
            }
        }

        throw new NotSupportedException($"BC parameter set '{parameterSetId}' not found in type '{parametersType.FullName}'.");
    }

    private static object GeneratePqcKeyPair(
        object parameters,
        SecureRandom random,
        string[] keyPairGeneratorTypeCandidates,
        string[] keyGenerationParametersTypeCandidates)
    {
        Type generatorType = ResolveRequiredType(keyPairGeneratorTypeCandidates);
        Type keyGenParamsType = ResolveRequiredType(keyGenerationParametersTypeCandidates);

        object keyGenParams = CreateKeyGenParameters(keyGenParamsType, parameters, random);
        object generator = Activator.CreateInstance(generatorType)
            ?? throw new NotSupportedException($"Unable to create generator '{generatorType.FullName}'.");

        InvokeRequiredVoidMethod(generator, "Init", keyGenParams);
        return InvokeRequiredMethod(generator, "GenerateKeyPair");
    }

    private static object CreateKeyGenParameters(Type keyGenParamsType, object parameters, SecureRandom random)
    {
        foreach (ConstructorInfo ctor in keyGenParamsType.GetConstructors())
        {
            ParameterInfo[] args = ctor.GetParameters();
            if (args.Length != 2)
                continue;

            if (ParameterAccepts(args[0].ParameterType, random) && ParameterAccepts(args[1].ParameterType, parameters))
                return ctor.Invoke(new object[] { random, parameters });

            if (ParameterAccepts(args[0].ParameterType, parameters) && ParameterAccepts(args[1].ParameterType, random))
                return ctor.Invoke(new object[] { parameters, random });
        }

        throw new NotSupportedException($"Unable to construct key generation parameters '{keyGenParamsType.FullName}'.");
    }

    private static object CreateKeyParameterFromEncoding(
        Type keyType,
        object parameterSet,
        ReadOnlySpan<byte> encoded)
    {
        byte[] bytes = encoded.ToArray();

        foreach (ConstructorInfo ctor in keyType.GetConstructors())
        {
            ParameterInfo[] args = ctor.GetParameters();

            if (args.Length == 2)
            {
                if (ParameterAccepts(args[0].ParameterType, parameterSet) && args[1].ParameterType == typeof(byte[]))
                    return ctor.Invoke(new object[] { parameterSet, bytes });

                if (args[0].ParameterType == typeof(byte[]) && ParameterAccepts(args[1].ParameterType, parameterSet))
                    return ctor.Invoke(new object[] { bytes, parameterSet });
            }

            if (args.Length == 1 && args[0].ParameterType == typeof(byte[]))
                return ctor.Invoke(new object[] { bytes });
        }

        foreach (MethodInfo method in keyType.GetMethods(BindingFlags.Public | BindingFlags.Static))
        {
            if (!string.Equals(method.Name, "FromEncoding", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(method.Name, "Create", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            ParameterInfo[] args = method.GetParameters();

            if (args.Length == 2)
            {
                if (ParameterAccepts(args[0].ParameterType, parameterSet) && args[1].ParameterType == typeof(byte[]))
                    return method.Invoke(null, new object[] { parameterSet, bytes })!;

                if (args[0].ParameterType == typeof(byte[]) && ParameterAccepts(args[1].ParameterType, parameterSet))
                    return method.Invoke(null, new object[] { bytes, parameterSet })!;
            }

            if (args.Length == 1 && args[0].ParameterType == typeof(byte[]))
                return method.Invoke(null, new object[] { bytes })!;
        }

        throw new NotSupportedException($"Unable to construct key parameter '{keyType.FullName}' from encoded bytes.");
    }

    private static void FeedSignerMessage(object signer, byte[] message)
    {
        MethodInfo? blockUpdate = signer.GetType().GetMethod(
            "BlockUpdate",
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            types: new[] { typeof(byte[]), typeof(int), typeof(int) },
            modifiers: null);

        if (blockUpdate is not null)
        {
            blockUpdate.Invoke(signer, new object[] { message, 0, message.Length });
            return;
        }

        MethodInfo? update = signer.GetType().GetMethod(
            "Update",
            BindingFlags.Instance | BindingFlags.Public,
            binder: null,
            types: new[] { typeof(byte[]), typeof(int), typeof(int) },
            modifiers: null);

        if (update is not null)
        {
            update.Invoke(signer, new object[] { message, 0, message.Length });
            return;
        }

        throw new NotSupportedException($"Unable to feed message into signer type '{signer.GetType().FullName}'.");
    }

    private static byte[] GetEncoded(object keyObject)
        => GetBytesFromRequiredMethod(keyObject, "GetEncoded");

    private static byte[] GetBytesFromRequiredMethod(object target, string methodName)
    {
        object result = InvokeRequiredMethod(target, methodName);

        if (result is byte[] b)
            return b;

        throw new NotSupportedException($"Method '{methodName}' on '{target.GetType().FullName}' did not return byte[].");
    }

    private static object GetRequiredMemberValue(object target, string memberName)
    {
        PropertyInfo? p = target.GetType().GetProperty(memberName, BindingFlags.Instance | BindingFlags.Public);
        if (p is not null)
            return p.GetValue(target) ?? throw new NotSupportedException($"Property '{memberName}' on '{target.GetType().FullName}' returned null.");

        FieldInfo? f = target.GetType().GetField(memberName, BindingFlags.Instance | BindingFlags.Public);
        if (f is not null)
            return f.GetValue(target) ?? throw new NotSupportedException($"Field '{memberName}' on '{target.GetType().FullName}' returned null.");

        throw new NotSupportedException($"Public member '{memberName}' not found on '{target.GetType().FullName}'.");
    }

    private static object InvokeRequiredMethod(object target, string methodName, params object[] args)
    {
        if (TryFindCompatibleMethod(target.GetType(), methodName, args, out MethodInfo? maybeMethod))
        {
            MethodInfo method = maybeMethod!;

            object? result = method.Invoke(target, args);

            if (method.ReturnType == typeof(void))
                throw new NotSupportedException($"Method '{methodName}' on '{target.GetType().FullName}' returns void; use InvokeRequiredVoidMethod.");

            return result ?? throw new NotSupportedException($"Method '{methodName}' on '{target.GetType().FullName}' returned null.");
        }

        throw new NotSupportedException($"Method '{methodName}' not found on '{target.GetType().FullName}'.");
    }

    private static void InvokeRequiredVoidMethod(object target, string methodName, params object[] args)
    {
        if (TryFindCompatibleMethod(target.GetType(), methodName, args, out MethodInfo? maybeMethod))
        {
            MethodInfo method = maybeMethod!;
            method.Invoke(target, args);
            return;
        }

        throw new NotSupportedException($"Method '{methodName}' not found on '{target.GetType().FullName}'.");
    }

    private static bool TryFindCompatibleMethod(Type type, string methodName, object[] args, out MethodInfo? method)
    {
        foreach (MethodInfo m in type.GetMethods(BindingFlags.Instance | BindingFlags.Public))
        {
            if (!string.Equals(m.Name, methodName, StringComparison.OrdinalIgnoreCase))
                continue;

            ParameterInfo[] p = m.GetParameters();
            if (p.Length != args.Length)
                continue;

            bool compatible = true;
            for (int i = 0; i < p.Length; i++)
            {
                if (!ParameterAccepts(p[i].ParameterType, args[i]))
                {
                    compatible = false;
                    break;
                }
            }

            if (compatible)
            {
                method = m;
                return true;
            }
        }

        method = null;
        return false;
    }

    private static bool ParameterAccepts(Type parameterType, object? arg)
    {
        if (arg is null)
            return !parameterType.IsValueType;

        if (parameterType.IsInstanceOfType(arg))
            return true;

        if (parameterType == typeof(byte[]) && arg is byte[])
            return true;

        if (parameterType == typeof(bool) && arg is bool)
            return true;

        return false;
    }

    /// <summary>
    /// Creates a PQC component instance, trying preferred constructor args first,
    /// then falling back to a parameterless constructor for older BC versions.
    /// </summary>
    private static object CreatePqcInstance(Type type, params object[] preferredCtorArgs)
    {
        foreach (ConstructorInfo ctor in type.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
        {
            ParameterInfo[] p = ctor.GetParameters();
            if (p.Length != preferredCtorArgs.Length)
                continue;

            bool match = true;
            for (int i = 0; i < p.Length; i++)
            {
                if (!ParameterAccepts(p[i].ParameterType, preferredCtorArgs[i]))
                {
                    match = false;
                    break;
                }
            }

            if (match)
                return ctor.Invoke(preferredCtorArgs);
        }

        // Fallback: parameterless (e.g. legacy DilithiumSigner)
        ConstructorInfo? defaultCtor = type.GetConstructor(
            BindingFlags.Public | BindingFlags.Instance, binder: null, Type.EmptyTypes, modifiers: null);
        if (defaultCtor is not null)
            return defaultCtor.Invoke(null);

        throw new NotSupportedException(
            $"Unable to create '{type.FullName}'. No compatible public constructor found.");
    }

    private static Type ResolveRequiredType(params string[] candidates)
        => ResolveRequiredType((IEnumerable<string>)candidates);

    private static Type ResolveRequiredType(IEnumerable<string> candidates)
    {
        foreach (string name in candidates)
        {
            Type? t = BcAssembly.GetType(name, throwOnError: false, ignoreCase: false);
            if (t is not null)
                return t;
        }

        throw new NotSupportedException("Required BC PQC type not found in current package.");
    }

    private static string NormalizeIdentifier(string value)
    {
        Span<char> buffer = stackalloc char[value.Length];
        int j = 0;
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            if (char.IsLetterOrDigit(c))
                buffer[j++] = char.ToLowerInvariant(c);
        }

        return new string(buffer[..j]);
    }
}
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace Cybersuite.Policy;

/// <summary>
/// Deterministic JSON canonicalization for policy hashing/signing.
/// Rules: UTF-8, NFC normalization for strings, lexicographic key ordering (Ordinal), no whitespace,
/// and exclusion of top-level "signature" property.
/// </summary>
public static class PolicyCanonicalizer
{
    public static byte[] CanonicalizePolicyUtf8(ReadOnlySpan<byte> policyUtf8)
    {
        var docOptions = new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64
        };

        // Fix: Use JsonDocument.Parse(ReadOnlyMemory<byte>, JsonDocumentOptions)
        using var doc = JsonDocument.Parse(policyUtf8.ToArray(), docOptions);
        if (doc.RootElement.ValueKind != JsonValueKind.Object)
            throw new PolicyValidationException("Policy root must be a JSON object.");

        return CanonicalizeRootObjectExcludingSignature(doc.RootElement);
    }

    private static byte[] CanonicalizeRootObjectExcludingSignature(JsonElement root)
    {
        var buffer = new ArrayBufferWriter<byte>(4096);
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false, SkipValidation = false }))
        {
            WriteObject(writer, root, isRoot: true);
            writer.Flush();
        }

        return buffer.WrittenSpan.ToArray();
    }

    private readonly struct Prop(string name, JsonElement value)
    {
        public readonly string Name { get; } = name;
        public readonly JsonElement Value { get; } = value;
    }

    private static void WriteObject(Utf8JsonWriter writer, JsonElement obj, bool isRoot)
    {
        var props = new List<Prop>();

        foreach (var p in obj.EnumerateObject())
        {
            if (isRoot && p.NameEquals("signature"))
                continue;

            props.Add(new Prop(p.Name, p.Value));
        }

        props.Sort((a, b) => StringComparer.Ordinal.Compare(a.Name, b.Name));

        writer.WriteStartObject();
        for (int i = 0; i < props.Count; i++)
        {
            var name = NormalizeString(props[i].Name);
            writer.WritePropertyName(name);
            WriteValue(writer, props[i].Value, isRoot: false);
        }
        writer.WriteEndObject();
    }

    private static void WriteArray(Utf8JsonWriter writer, JsonElement array)
    {
        writer.WriteStartArray();
        foreach (var e in array.EnumerateArray())
            WriteValue(writer, e, isRoot: false);
        writer.WriteEndArray();
    }

    private static void WriteValue(Utf8JsonWriter writer, JsonElement value, bool isRoot)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Object:
                WriteObject(writer, value, isRoot);
                return;

            case JsonValueKind.Array:
                WriteArray(writer, value);
                return;

            case JsonValueKind.String:
                writer.WriteStringValue(NormalizeString(value.GetString() ?? string.Empty));
                return;

            case JsonValueKind.Number:
                if (value.TryGetInt64(out long i64))
                {
                    writer.WriteNumberValue(i64);
                    return;
                }
                throw new PolicyValidationException("Non-integer numbers are not allowed in policy canonicalization.");

            case JsonValueKind.True:
                writer.WriteBooleanValue(true);
                return;

            case JsonValueKind.False:
                writer.WriteBooleanValue(false);
                return;

            case JsonValueKind.Null:
                writer.WriteNullValue();
                return;

            default:
                throw new PolicyValidationException($"Unsupported JSON token in policy: {value.ValueKind}");
        }
    }

    private static string NormalizeString(string s)
        => s.Normalize(NormalizationForm.FormC);
}
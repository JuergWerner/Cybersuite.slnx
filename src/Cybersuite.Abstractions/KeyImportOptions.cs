namespace Cybersuite.Abstractions;

/// <summary>
/// Immutable import options for key material.
/// This structure carries only non-secret metadata.
/// The encoded key bytes themselves are passed separately.
/// </summary>
public readonly record struct KeyImportOptions(
    AlgorithmId AlgorithmId,
    AlgorithmParameterSetId? ParameterSetId,
    AlgorithmEncodingProfile EncodingProfile
);
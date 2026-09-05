import { LIMITS, RESULT_METADATA_RESERVATION_BYTES } from "../core/limits.js";
import { runtimeInfo } from "../core/runtime.js";
import { compareUtf16CodeUnits } from "../core/string-order.js";
import { unicodeDataIdentity } from "../core/unicode-security-data.js";
import { UTS46_ENGINE_IDENTITY } from "../core/protocol-engine.js";
import { PRODUCT_NAME, VERSION } from "../version.js";
import { canonicalDigest, canonicalJson, merkleRoot } from "./canonical.js";
import {
  MEASUREMENT_COMPARISON_LIMITS,
  MEASUREMENT_COMPARISON_SCHEMA_VERSION,
  compareMeasurementRecords
} from "./measurement-comparison.js";
import {
  COLLATION_CALIBRATION_SCHEMA_VERSION,
  createCollationCalibration
} from "./collation-calibration.js";
import {
  COLLATION_COMPARISON_LIMITS,
  COLLATION_COMPARISON_SCHEMA_VERSION,
  compareCollationCalibrations
} from "./collation-comparison.js";
import {
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS,
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_LIMITS,
  PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION,
  createPackageReplaySidecar,
  verifyPackageReplaySidecarBytes
} from "./package-replay-sidecar.js";
import {
  PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS,
  PACKAGE_REPLAY_SIDECAR_COMPARISON_SCHEMA_VERSION,
  REPLAY_RECEIPT_COMPARISON_LIMITS,
  REPLAY_RECEIPT_COMPARISON_SCHEMA_VERSION,
  comparePackageReplaySidecars,
  compareReplayReceipts
} from "./replay-comparison.js";
import {
  REFERENCE_SOURCE_FILES,
  REPLAY_INSTALLED_RUNTIME_FILES,
  REPLAY_RECEIPT_LIMITS,
  REPLAY_RECEIPT_SCHEMA_VERSION,
  createReplayReceipt
} from "./replay-receipt.js";
import {
  PROPERTY_VERIFICATION_LIMITS,
  PROPERTY_VERIFICATION_SCHEMA_VERSION,
  runPropertyVerification
} from "./property-verification.js";
import {
  BEHAVIOR_COMPARISON_SCHEMA_VERSION,
  BEHAVIOR_CORPUS_SCHEMA_VERSION,
  BEHAVIOR_MANIFEST_SCHEMA_VERSION,
  ENVIRONMENT_PROJECTION_SCHEMA_VERSION,
  MEASUREMENT_RECORD_SCHEMA_VERSION,
  MEASUREMENT_REPLAY_SCHEMA_VERSION,
  PUBLIC_RESULT_SCHEMA_VERSION,
  SEMANTIC_PROJECTION_SCHEMA_VERSION,
  TAGGED_REQUEST_SCHEMA_VERSION
} from "./versions.js";
import {
  MEASUREMENT_RECORD_LIMITS,
  MEASUREMENT_REPLAY_LIMITS,
  REPRODUCIBILITY_TARGETS,
  SUPPORTED_REFERENCE_OPERATIONS,
  caseReproducibilityTarget,
  createMeasurementRecord,
  environmentProjection,
  materializeTaggedArguments,
  measureReferenceRequest,
  parseMeasurementRecord,
  replayMeasurementRecord,
  semanticProjection,
  validateMeasurementRecord
} from "./measurement.js";

export {
  COLLATION_CALIBRATION_SCHEMA_VERSION,
  COLLATION_COMPARISON_LIMITS,
  COLLATION_COMPARISON_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS,
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS,
  PACKAGE_REPLAY_SIDECAR_COMPARISON_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_LIMITS,
  PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION,
  MEASUREMENT_COMPARISON_LIMITS,
  MEASUREMENT_COMPARISON_SCHEMA_VERSION,
  PROPERTY_VERIFICATION_LIMITS,
  PROPERTY_VERIFICATION_SCHEMA_VERSION,
  REFERENCE_SOURCE_FILES,
  REPLAY_INSTALLED_RUNTIME_FILES,
  REPLAY_RECEIPT_COMPARISON_LIMITS,
  REPLAY_RECEIPT_COMPARISON_SCHEMA_VERSION,
  REPLAY_RECEIPT_LIMITS,
  REPLAY_RECEIPT_SCHEMA_VERSION,
  compareCollationCalibrations,
  compareMeasurementRecords,
  comparePackageReplaySidecars,
  compareReplayReceipts,
  createCollationCalibration,
  createPackageReplaySidecar,
  createReplayReceipt,
  runPropertyVerification,
  verifyPackageReplaySidecarBytes
};
export {
  BEHAVIOR_COMPARISON_SCHEMA_VERSION,
  BEHAVIOR_CORPUS_SCHEMA_VERSION,
  BEHAVIOR_MANIFEST_SCHEMA_VERSION,
  ENVIRONMENT_PROJECTION_SCHEMA_VERSION,
  MEASUREMENT_RECORD_SCHEMA_VERSION,
  MEASUREMENT_REPLAY_SCHEMA_VERSION,
  PUBLIC_RESULT_SCHEMA_VERSION,
  SEMANTIC_PROJECTION_SCHEMA_VERSION,
  TAGGED_REQUEST_SCHEMA_VERSION
};
export {
  MEASUREMENT_RECORD_LIMITS,
  MEASUREMENT_REPLAY_LIMITS,
  REPRODUCIBILITY_TARGETS,
  SUPPORTED_REFERENCE_OPERATIONS,
  caseReproducibilityTarget,
  createMeasurementRecord,
  environmentProjection,
  materializeTaggedArguments,
  measureReferenceRequest,
  parseMeasurementRecord,
  replayMeasurementRecord,
  semanticProjection,
  validateMeasurementRecord
};
const VERIFICATION_STATUS = Object.freeze({
  explain_difference: "scoped_native_wasm_parity",
  index: "native_wasm_parity",
  inspect: "native_wasm_parity",
  namespace_integrity: "scoped_native_wasm_parity",
  normalize: "native_wasm_parity",
  protocol_profile: "native_wasm_parity",
  security: "native_wasm_parity",
  transcode: "native_wasm_parity"
});

const INDEPENDENT_VERIFICATION = Object.freeze({
  explain_difference: Object.freeze({
    canonicalCaseCount: 2,
    additionalComparisonCaseCount: 42966,
    totalCaseCount: 42968,
    implementations: Object.freeze([
      "node_composed_core_with_runtime_icu_projected_out",
      "rust_generated_unicode17_native",
      "rust_generated_unicode17_wasm32_unknown_unknown"
    ]),
    dataAuthority: "same_pinned_unicode_source",
    projectionExcludedFields: Object.freeze([
      "collation",
      "runtime",
      "identifierConfusableComparison.engine"
    ]),
    scope: Object.freeze({
      kind: "deterministic_spine",
      includedStages: Object.freeze([
        "exact_representation",
        "normalization",
        "nfkc_casefold",
        "coordinate_mapping",
        "alignment",
        "unicode_signals",
        "line_endings",
        "identifier_confusable"
      ]),
      excludedStages: Object.freeze(["collation"]),
      requiresValidNodeCollationRequest: true,
      completeConsumerParity: false
    }),
    graphemeConformanceCaseCount: 766,
    normalizationConformanceCaseCount: 20034,
    nfkcCasefoldCaseCount: 11662,
    confusableComparisonCaseCount: 10433,
    signalBoundaryCaseCount: 58,
    composedSequenceCaseCount: 13
  }),
  index: Object.freeze({
    canonicalCaseCount: 2,
    additionalComparisonCaseCount: 984,
    totalCaseCount: 986,
    negativeRequestShapeCaseCount: 18,
    packagedReferenceWasmNegativeRequestShapeCaseCount: 18
  }),
  inspect: Object.freeze({
    canonicalCaseCount: 3,
    additionalComparisonCaseCount: 1299,
    totalCaseCount: 1302,
    negativeRequestShapeCaseCount: 11,
    packagedReferenceWasmNegativeRequestShapeCaseCount: 11
  }),
  namespace_integrity: Object.freeze({
    canonicalCaseCount: 2,
    additionalComparisonCaseCount: 239,
    totalCaseCount: 241,
    implementations: Object.freeze([
      "node_composed_unicode17_core_with_runtime_icu_collation_excluded",
      "rust_generated_unicode17_and_configurable_uts46_native",
      "rust_generated_unicode17_and_configurable_uts46_wasm32_unknown_unknown"
    ]),
    dataAuthority: "locked_independent_uts46_engines_and_same_pinned_unicode_source_for_other_relations",
    projectionExcludedFields: Object.freeze(["runtime"]),
    scope: Object.freeze({
      includedRelations: Object.freeze([
        "exact",
        "nfc",
        "nfkc",
        "nfkc_casefold",
        "uts39_confusable",
        "protocol:uts46_domain",
        "protocol:precis_username_case_mapped",
        "protocol:precis_username_case_preserved",
        "protocol:precis_opaque_string"
      ]),
      excludedRelations: Object.freeze(["declared_collation"]),
      completeConsumerParity: false,
      deterministicUtf16Ordering: true,
      requestShapeValidationIncluded: true,
      completeResultBudgetEnforcementImplemented: true,
      runtimeDependentBudgetDiagnosticsExcluded: true
    }),
    simpleDirectionCaseCount: 3,
    utf16OrderingCaseCount: 1,
    uts46ConfigurationCaseCount: 192,
    precisProfileCaseCount: 3,
    composedProtocolRelationCaseCount: 1,
    negativeCaseCount: 39
  }),
  normalize: Object.freeze({
    canonicalCaseCount: 5,
    additionalComparisonCaseCount: 80248,
    totalCaseCount: 80253,
    negativeRequestShapeCaseCount: 16,
    packagedReferenceWasmNegativeRequestShapeCaseCount: 16
  }),
  protocol_profile: Object.freeze({
    canonicalCaseCount: 5,
    additionalComparisonCaseCount: 68149,
    totalCaseCount: 68154,
    officialInputCaseCount: 6389,
    officialOperationCaseCount: 19167,
    implementations: Object.freeze([
      "node_tr46_6_0_0_and_unicode17_precis_core",
      "rust_idna_adapter_1_2_1_configurable_uts46_and_generated_unicode17_precis_native",
      "rust_idna_adapter_1_2_1_configurable_uts46_and_generated_unicode17_precis_wasm32_unknown_unknown"
    ]),
    dataAuthority: "locked_independent_uts46_engines_and_same_pinned_unicode_source_for_precis",
    projectionExcludedFields: Object.freeze(["standards.engine", "witness.engine"]),
    scope: Object.freeze({
      uts46: Object.freeze({
        profile: "uts46_domain",
        actions: Object.freeze(["to_ascii", "to_unicode"]),
        witnessModes: Object.freeze(["none", "summary", "full_required"]),
        implementationScope: "complete_option_space",
        requestShapeValidationIncluded: true
      }),
      precis: Object.freeze({
        profiles: Object.freeze([
          "precis_username_case_mapped",
          "precis_username_case_preserved",
          "precis_opaque_string"
        ]),
        actions: Object.freeze(["enforce", "compare"]),
        witnessModes: Object.freeze(["none", "summary", "full_required"]),
        implementationScope: "complete_profile_execution",
        requestShapeValidationIncluded: true
      })
    }),
    uts46Options: Object.freeze({
      probeCount: 19,
      toAsciiOptionCombinationCount: 128,
      toUnicodeOptionCombinationCount: 64,
      allLegalOptionCombinationsIncluded: true,
      totalCaseCount: 3648
    }),
    requestShape: Object.freeze({
      sharedCaseCount: 4,
      uts46CaseCount: 26,
      precisCaseCount: 14,
      totalCaseCount: 44
    }),
    precis: Object.freeze({
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      sourceFiles: Object.freeze({
        derivedCore: Object.freeze({ path: "ucd/DerivedCoreProperties.txt", sha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08" }),
        propList: Object.freeze({ path: "ucd/PropList.txt", sha256: "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd" }),
        generalCategory: Object.freeze({ path: "ucd/extracted/DerivedGeneralCategory.txt", sha256: "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e" }),
        unicodeData: Object.freeze({ path: "ucd/UnicodeData.txt", sha256: "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c" }),
        specialCasing: Object.freeze({ path: "ucd/SpecialCasing.txt", sha256: "efc25faf19de21b92c1194c111c932e03d2a5eaf18194e33f1156e96de4c9588" }),
        joiningType: Object.freeze({ path: "ucd/extracted/DerivedJoiningType.txt", sha256: "f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d" }),
        hangulSyllableType: Object.freeze({ path: "ucd/HangulSyllableType.txt", sha256: "5a57450afde0d082bc5026f7458649eac3b615490cc7e3d916b0367f1593c0e3" }),
        scripts: Object.freeze({ path: "ucd/Scripts.txt", sha256: "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf" }),
        scriptExtensions: Object.freeze({ path: "ucd/ScriptExtensions.txt", sha256: "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6" }),
        bidiClass: Object.freeze({ path: "ucd/extracted/DerivedBidiClass.txt", sha256: "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4" })
      }),
      propertyBoundaryCodePointCount: 7819,
      propertyBoundaryProfileCaseCount: 23457,
      widthMappingCaseCount: 226,
      lowercaseMappingCaseCount: 1488,
      normalizationConformanceSourceCaseCount: 20034,
      contextSequenceCaseCount: 48,
      bidiSequenceCaseCount: 18,
      composedSequenceCaseCount: 17,
      negativeEncodingCaseCount: 2,
      totalCaseCount: 45290
    })
  }),
  security: Object.freeze({
    canonicalCaseCount: 4,
    additionalComparisonCaseCount: 39010,
    totalCaseCount: 39014,
    implementations: Object.freeze([
      "node_compact_unicode17_bidi_js_1_0_3",
      "rust_generated_unicode17_unicode_bidi_0_3_18_native",
      "rust_generated_unicode17_unicode_bidi_0_3_18_wasm32_unknown_unknown"
    ]),
    dataAuthority: "same_pinned_unicode_source",
    projectionExcludedFields: Object.freeze(["confusableComparison.engine"]),
    scope: Object.freeze({
      modes: Object.freeze(["free_text", "identifier", "source"])
    }),
    sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
    sourceFiles: Object.freeze({
      identifierStatus: Object.freeze({ path: "security/IdentifierStatus.txt", sha256: "617228a16da13850bf8af28b6cd08f5e9b6595d2eb60404fe6eee2c85b4e4a35" }),
      identifierType: Object.freeze({ path: "security/IdentifierType.txt", sha256: "924ac63faa97ed73420d6ac48d08279d90968c7da0502ab701e08bfbb9683c22" }),
      derivedCore: Object.freeze({ path: "ucd/DerivedCoreProperties.txt", sha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08" }),
      propList: Object.freeze({ path: "ucd/PropList.txt", sha256: "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd" }),
      generalCategory: Object.freeze({ path: "ucd/extracted/DerivedGeneralCategory.txt", sha256: "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e" }),
      unicodeData: Object.freeze({ path: "ucd/UnicodeData.txt", sha256: "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c" }),
      scripts: Object.freeze({ path: "ucd/Scripts.txt", sha256: "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf" }),
      scriptExtensions: Object.freeze({ path: "ucd/ScriptExtensions.txt", sha256: "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6" }),
      bidiClass: Object.freeze({ path: "ucd/extracted/DerivedBidiClass.txt", sha256: "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4" }),
      nfkcCasefold: Object.freeze({ path: "ucd/DerivedNormalizationProps.txt", sha256: "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488" }),
      confusables: Object.freeze({ path: "security/confusables.txt", sha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a" })
    }),
    propertyBoundaryCaseCount: 10034,
    freeTextBoundaryCaseCount: 58,
    xidProfileCaseCount: 5084,
    nfkcCasefoldProfileCaseCount: 10583,
    confusableEnvelopeCaseCount: 6565,
    sequenceCaseCount: 13,
    negativeCaseCount: 14,
    sourceDiagnostics: Object.freeze({
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      sourceFiles: Object.freeze({
        derivedCore: Object.freeze({ path: "ucd/DerivedCoreProperties.txt", sha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08" }),
        propList: Object.freeze({ path: "ucd/PropList.txt", sha256: "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd" }),
        generalCategory: Object.freeze({ path: "ucd/extracted/DerivedGeneralCategory.txt", sha256: "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e" }),
        confusables: Object.freeze({ path: "security/confusables.txt", sha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a" })
      }),
      signalBoundaryCaseCount: 58,
      confusableEnvelopeCaseCount: 6565,
      sequenceCaseCount: 7,
      negativeCaseCount: 29,
      totalCaseCount: 6659
    })
  }),
  transcode: Object.freeze({
    canonicalCaseCount: 4,
    additionalComparisonCaseCount: 1587,
    totalCaseCount: 1591,
    negativeRequestShapeCaseCount: 45,
    packagedReferenceWasmNegativeRequestShapeCaseCount: 45
  })
});

const PRIMITIVE_VERIFICATION = Object.freeze({
  bidiSkeleton: Object.freeze({
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: Object.freeze(["explain_difference", "namespace_integrity", "security", "source_diagnostics"]),
    verificationStatus: "scoped_native_wasm_parity",
    claimBoundary: "complete Unicode 17 bidiSkeleton value and paragraph levels only; X9-excluded engine diagnostics and consumer envelopes remain separately classified",
    independentVerification: Object.freeze({
      command: "npm run check:independent",
      implementations: Object.freeze([
        "node_bidi_js_1_0_3_generated_unicode17",
        "rust_unicode_bidi_0_3_18_generated_unicode17_native",
        "rust_unicode_bidi_0_3_18_generated_unicode17_wasm32_unknown_unknown"
      ]),
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: Object.freeze([
        "engine",
        "standards.uba.algorithm",
        "standards.uba.hardcodedDataFeature",
        "standards.uba.dataSource",
        "resolvedLevels",
        "visualOrder",
        "entries",
        "reordered"
      ]),
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      bidiClassSourcePath: "ucd/extracted/DerivedBidiClass.txt",
      bidiClassSourceSha256: "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4",
      scalarBoundaryCodePointCount: 3795,
      scalarBoundaryDirectionCaseCount: 11385,
      bidiBracketsSourcePath: "ucd/BidiBrackets.txt",
      bidiBracketsSourceSha256: "dadbaf38a0d0246e5b805bf8725cb81b7c621f93d030595635f5ba2c2f179428",
      bracketEntryCount: 128,
      bracketDirectionCaseCount: 384,
      bidiMirroringSourcePath: "ucd/BidiMirroring.txt",
      bidiMirroringSourceSha256: "a2f16fb873ab4fcdf3221cb1a8a85a134ddd6ed03603181823ff5206af3741ce",
      mirroringEntryCount: 428,
      unicodeDataSourcePath: "ucd/UnicodeData.txt",
      unicodeDataSourceSha256: "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
      combiningCodePointCount: 968,
      conformanceManifestSha256: "61c3f102afd997d929634ea5170e094a2d9808394113d6d749f8f448b1a5497d",
      bidiTestCompressedSha256: "b1e05b09dbd0a03dca1ed880f41c4002de38ef57adca88ac4052b8ef17a7249e",
      bidiTestParagraphModeCaseCount: 770241,
      bidiTestSampleCount: 2997,
      bidiCharacterTestCompressedSha256: "8b80599d288bad03ed420564ae0a6b7b92cc63027f55d51c6d55ad56ede85e54",
      bidiCharacterTestCaseCount: 91707,
      bidiCharacterTestSampleCount: 717,
      sequenceCaseCount: 42,
      totalCaseCount: 16921
    })
  }),
  confusableComparison: Object.freeze({
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: Object.freeze(["explain_difference", "namespace_integrity", "security", "source_diagnostics"]),
    verificationStatus: "native_wasm_parity",
    claimBoundary: "Unicode 17 resolved-script sets and complete UTS #39 confusable relation, class, paragraph levels, and skeleton digests only; consumer envelopes remain separately classified",
    independentVerification: Object.freeze({
      command: "npm run check:independent",
      implementations: Object.freeze([
        "node_compact_unicode17_bidi_js_1_0_3",
        "rust_generated_unicode17_unicode_bidi_0_3_18_native",
        "rust_generated_unicode17_unicode_bidi_0_3_18_wasm32_unknown_unknown"
      ]),
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: Object.freeze(["engine"]),
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      scriptsSourcePath: "ucd/Scripts.txt",
      scriptsSourceSha256: "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf",
      scriptExtensionsSourcePath: "ucd/ScriptExtensions.txt",
      scriptExtensionsSourceSha256: "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6",
      propertyValueAliasesSourcePath: "ucd/PropertyValueAliases.txt",
      propertyValueAliasesSourceSha256: "64e9a5f76f7a1e8b5a47d6a1f9a26522a251208f5276bdfa1559dac7cf2e827a",
      scriptBoundaryCaseCount: 3826,
      confusablesSourcePath: "security/confusables.txt",
      confusablesSourceSha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
      confusableMappingCaseCount: 6565,
      sequenceCaseCount: 42,
      totalCaseCount: 10433
    })
  }),
  nfkcCasefold: Object.freeze({
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: Object.freeze(["explain_difference", "namespace_integrity", "security"]),
    verificationStatus: "native_wasm_parity",
    claimBoundary: "NFKC_CF mapping followed by Unicode 17 NFC only; consumer operations remain separately classified",
    independentVerification: Object.freeze({
      command: "npm run check:independent",
      implementations: Object.freeze([
        "node_compact_unicode17",
        "rust_generated_unicode17_native",
        "rust_generated_unicode17_wasm32_unknown_unknown"
      ]),
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: Object.freeze(["engine"]),
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      sourceFilePath: "ucd/DerivedNormalizationProps.txt",
      sourceFileSha256: "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488",
      mappingRowCount: 6183,
      mappedCodePointCaseCount: 10583,
      identityBoundaryCaseCount: 1063,
      sequenceCaseCount: 16,
      totalCaseCount: 11662
    })
  }),
  uts39PostReorderSkeleton: Object.freeze({
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: Object.freeze(["explain_difference", "namespace_integrity", "security"]),
    verificationStatus: "native_wasm_parity",
    claimBoundary: "post-reorder NFD, Default_Ignorable removal, confusable mapping, and final NFD only; UBA reordering and consumer operations remain separately classified",
    independentVerification: Object.freeze({
      command: "npm run check:independent",
      implementations: Object.freeze([
        "node_compact_unicode17_uts39_revision32",
        "rust_generated_unicode17_uts39_revision32_native",
        "rust_generated_unicode17_uts39_revision32_wasm32_unknown_unknown"
      ]),
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: Object.freeze(["engine"]),
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      confusablesSourcePath: "security/confusables.txt",
      confusablesSourceSha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
      derivedCoreSourcePath: "ucd/DerivedCoreProperties.txt",
      derivedCoreSourceSha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08",
      confusableMappingRowCount: 6565,
      mappedSourceCaseCount: 6565,
      defaultIgnorableRangeCount: 27,
      defaultIgnorableCodePointCount: 4174,
      defaultIgnorableCaseCount: 4174,
      identityBoundaryCaseCount: 2607,
      sequenceCaseCount: 24,
      normalizationConformanceSourceCaseCount: 20034,
      totalCaseCount: 33404
    })
  })
});

function requireClosedKeys(value, allowed, required, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object.`);
  }
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new TypeError(`${field} has unknown fields: ${unknown.sort().join(", ")}.`);
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  if (missing.length > 0) throw new TypeError(`${field} is missing fields: ${missing.join(", ")}.`);
}

function validateCorpus(corpus) {
  requireClosedKeys(corpus, ["schemaVersion", "cases"], ["schemaVersion", "cases"], "corpus");
  if (corpus.schemaVersion !== BEHAVIOR_CORPUS_SCHEMA_VERSION || !Array.isArray(corpus.cases)) {
    throw new TypeError("The behavior corpus has an unsupported schema or cases value.");
  }
  const ids = new Set();
  for (const [index, entry] of corpus.cases.entries()) {
    const field = `corpus.cases[${index}]`;
    requireClosedKeys(entry, ["id", "operation", "arguments"], ["id", "operation", "arguments"], field);
    if (typeof entry.id !== "string" || entry.id === "" || !entry.id.isWellFormed() || ids.has(entry.id)) {
      throw new TypeError(`${field}.id must be a unique non-empty well-formed string.`);
    }
    if (!SUPPORTED_REFERENCE_OPERATIONS.includes(entry.operation)) {
      throw new TypeError(`${field}.operation is not supported.`);
    }
    ids.add(entry.id);
  }
}

export function createBehaviorManifest(corpus) {
  validateCorpus(corpus);
  const cases = [...corpus.cases]
    .sort((left, right) => compareUtf16CodeUnits(left.id, right.id))
    .map((entry) => {
      const request = { operation: entry.operation, arguments: entry.arguments };
      const measured = measureReferenceRequest(request);
      return {
        id: entry.id,
        operation: entry.operation,
        reproducibilityTarget: measured.reproducibilityTarget,
        requestSha256: measured.requestSha256,
        semanticSha256: measured.semanticSha256,
        environmentSha256: measured.environmentSha256,
        resultSha256: measured.completeResultSha256
      };
    });

  const operations = Object.fromEntries(SUPPORTED_REFERENCE_OPERATIONS.map((operation) => {
    const operationCases = cases.filter((entry) => entry.operation === operation);
    return [operation, {
      reproducibilityTarget: REPRODUCIBILITY_TARGETS[operation],
      verificationStatus: VERIFICATION_STATUS[operation] ?? "single_implementation",
      ...(Object.hasOwn(INDEPENDENT_VERIFICATION, operation) ? {
        independentVerification: {
          command: "npm run check:independent",
          implementations: ["node", "rust_native", "rust_wasm32_unknown_unknown"],
          ...INDEPENDENT_VERIFICATION[operation]
        }
      } : {}),
      caseCount: operationCases.length,
      semanticRootSha256: merkleRoot(operationCases.map(({ id, requestSha256, semanticSha256 }) => ({
        id,
        requestSha256,
        semanticSha256
      })))
    }];
  }));

  return {
    schemaVersion: BEHAVIOR_MANIFEST_SCHEMA_VERSION,
    product: { name: PRODUCT_NAME, version: VERSION },
    contracts: {
      taggedRequest: TAGGED_REQUEST_SCHEMA_VERSION,
      publicResult: PUBLIC_RESULT_SCHEMA_VERSION,
      measurementRecord: MEASUREMENT_RECORD_SCHEMA_VERSION,
      measurementComparison: MEASUREMENT_COMPARISON_SCHEMA_VERSION
    },
    corpus: {
      schemaVersion: corpus.schemaVersion,
      caseCount: cases.length,
      sha256: canonicalDigest(corpus)
    },
    data: unicodeDataIdentity(),
    engines: {
      uts46: UTS46_ENGINE_IDENTITY,
      collation: createCollationCalibration()
    },
    semanticProjection: {
      schemaVersion: SEMANTIC_PROJECTION_SCHEMA_VERSION,
      excludedFields: [
        "runtime",
        "confusableComparison.engine",
        "identifierConfusableComparison.engine",
        "standards.engine",
        "witness.engine",
        "error.details.actualBytes for RESULT_TOO_LARGE",
        "error.details.metadataBytes for RESULT_TOO_LARGE"
      ],
      resultBudget: {
        maxBytes: LIMITS.maxResultBytes,
        semanticBytesPlusMetadataReservation: true,
        metadataReservationBytes: RESULT_METADATA_RESERVATION_BYTES
      }
    },
    environmentProjection: {
      schemaVersion: ENVIRONMENT_PROJECTION_SCHEMA_VERSION,
      includedFields: [
        "runtime",
        "confusableComparison.engine",
        "identifierConfusableComparison.engine",
        "standards.engine",
        "witness.engine",
        "error.details.actualBytes for RESULT_TOO_LARGE",
        "error.details.metadataBytes for RESULT_TOO_LARGE"
      ]
    },
    primitives: PRIMITIVE_VERIFICATION,
    environment: runtimeInfo(),
    operations,
    cases,
    behaviorRootSha256: merkleRoot(cases.map(({ id, operation, requestSha256, semanticSha256 }) => ({
      id,
      operation,
      requestSha256,
      semanticSha256
    })))
  };
}

export function compareBehaviorManifests(before, after) {
  if (before?.schemaVersion !== BEHAVIOR_MANIFEST_SCHEMA_VERSION
    || after?.schemaVersion !== BEHAVIOR_MANIFEST_SCHEMA_VERSION) {
    throw new TypeError("Both behavior manifests must use the supported schema version.");
  }
  const beforeCases = new Map(before.cases.map((entry) => [entry.id, entry]));
  const afterCases = new Map(after.cases.map((entry) => [entry.id, entry]));
  const ids = [...new Set([...beforeCases.keys(), ...afterCases.keys()])].sort(compareUtf16CodeUnits);
  const dataIdentityChanged = canonicalDigest(before.data) !== canonicalDigest(after.data);
  const uts46EngineChanged = canonicalDigest(before.engines.uts46)
    !== canonicalDigest(after.engines.uts46);
  const collation = compareCollationCalibrations(
    before.engines.collation,
    after.engines.collation
  );
  const engineIdentityChanged = uts46EngineChanged || collation.changed;
  const verificationMetadata = (manifest) => ({
    contracts: manifest.contracts,
    semanticProjection: manifest.semanticProjection,
    environmentProjection: manifest.environmentProjection,
    primitives: manifest.primitives,
    operations: Object.fromEntries(Object.entries(manifest.operations).map(([operation, value]) => [
      operation,
      {
        verificationStatus: value.verificationStatus,
        ...(value.independentVerification === undefined
          ? {}
          : { independentVerification: value.independentVerification })
      }
    ]))
  });
  const verificationMetadataChanged = canonicalDigest(verificationMetadata(before))
    !== canonicalDigest(verificationMetadata(after));
  const changes = ids.flatMap((id) => {
    const oldEntry = beforeCases.get(id);
    const newEntry = afterCases.get(id);
    if (!oldEntry) return [{ id, kind: "case_added", operation: newEntry.operation }];
    if (!newEntry) return [{ id, kind: "case_removed", operation: oldEntry.operation }];
    if (oldEntry.requestSha256 !== newEntry.requestSha256 || oldEntry.operation !== newEntry.operation) {
      return [{ id, kind: "request_changed", operation: newEntry.operation }];
    }
    if (oldEntry.semanticSha256 !== newEntry.semanticSha256) {
      return [{ id, kind: "semantic_changed", operation: newEntry.operation }];
    }
    if (oldEntry.environmentSha256 !== newEntry.environmentSha256
      || oldEntry.resultSha256 !== newEntry.resultSha256) {
      return [{ id, kind: "environment_metadata_changed", operation: newEntry.operation }];
    }
    return [];
  });
  return {
    schemaVersion: BEHAVIOR_COMPARISON_SCHEMA_VERSION,
    before: {
      product: before.product,
      data: before.data,
      engines: {
        uts46: before.engines.uts46,
        collation: collation.before
      },
      behaviorRootSha256: before.behaviorRootSha256
    },
    after: {
      product: after.product,
      data: after.data,
      engines: {
        uts46: after.engines.uts46,
        collation: collation.after
      },
      behaviorRootSha256: after.behaviorRootSha256
    },
    changed: dataIdentityChanged || engineIdentityChanged || verificationMetadataChanged || changes.length > 0,
    dataIdentityChanged,
    engineIdentityChanged,
    engineChanges: {
      uts46Changed: uts46EngineChanged,
      collation
    },
    verificationMetadataChanged,
    changes,
    unclassifiedSemanticChanges: changes.filter((entry) => entry.kind === "semantic_changed").length
  };
}

export { canonicalDigest, canonicalJson, merkleRoot } from "./canonical.js";

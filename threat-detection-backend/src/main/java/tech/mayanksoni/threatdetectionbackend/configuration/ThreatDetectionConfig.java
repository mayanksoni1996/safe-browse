package tech.mayanksoni.threatdetectionbackend.configuration;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the threat detection system.
 */
@ConfigurationProperties(prefix = "threatdetection")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
public class ThreatDetectionConfig {
    /**
     * The threshold for edit distance comparison.
     * Domains with an edit distance less than or equal to this value will be considered typosquatting attempts.
     */
    private int editDistanceThreshold;

    /**
     * Whether to enable phonetic matching for domain comparison.
     */
    @Builder.Default
    private boolean enablePhoneticMatching = true;

    /**
     * Whether to use Soundex algorithm for phonetic matching.
     */
    @Builder.Default
    private boolean enableSoundex = true;

    /**
     * Whether to use Metaphone algorithm for phonetic matching.
     */
    @Builder.Default
    private boolean enableMetaphone = true;

    /**
     * Whether to use Double Metaphone algorithm for phonetic matching.
     */
    @Builder.Default
    private boolean enableDoubleMetaphone = true;

    /**
     * Whether to enable parallel processing for batch domain checks.
     */
    @Builder.Default
    private boolean enableParallelProcessing = true;

    /**
     * The maximum number of threads to use for parallel processing.
     * If not specified, it will use the number of available processors.
     */
    @Builder.Default
    private int maxThreads = Runtime.getRuntime().availableProcessors();

    /**
     * The batch size for processing domains in parallel.
     */
    @Builder.Default
    private int batchSize = 100;
}

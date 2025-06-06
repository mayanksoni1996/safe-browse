package tech.mayanksoni.threatdetectionbackend.services;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tech.mayanksoni.threatdetectionbackend.configuration.ThreatDetectionConfig;
import tech.mayanksoni.threatdetectionbackend.dm.TrustedDomainDataManager;
import tech.mayanksoni.threatdetectionbackend.models.DomainTyposquattingValidationResults;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;
import tech.mayanksoni.threatdetectionbackend.utils.DomainUtils;
import tech.mayanksoni.threatdetectionbackend.utils.EditDistanceUtil;
import tech.mayanksoni.threatdetectionbackend.utils.PhoneticMatchingUtil;
import tech.mayanksoni.threatdetectionbackend.utils.ThreatIntelFileSystemUtils;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

@Service
@Slf4j
@RequiredArgsConstructor
public class TyposquattingDetectionService {
    private final TrustedDomainDataManager trustedDomainDataManager;
    private final ThreatDetectionConfig threatDetectionConfig;
    private int EDIT_DISTANCE_THRESHOLD;
    private ThreadPoolExecutor executor;

    @PostConstruct
    public void performPostInitialization() {
        this.EDIT_DISTANCE_THRESHOLD = threatDetectionConfig.getEditDistanceThreshold();
        log.info("TyposquattingDetectionService initialized with EDIT_DISTANCE_THRESHOLD: {}", EDIT_DISTANCE_THRESHOLD);

        // Initialize thread pool for parallel processing if enabled
        if (threatDetectionConfig.isEnableParallelProcessing()) {
            this.executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(threatDetectionConfig.getMaxThreads());
            log.info("Parallel processing enabled with {} threads", threatDetectionConfig.getMaxThreads());
        }

        List<String[]> trustedDomainsFromTrancoFile = ThreatIntelFileSystemUtils.readCsvFileFromFileSystem(Paths.get(System.getenv("TRANCO_FILEPATH")));
        int fileRecordsCount = trustedDomainsFromTrancoFile.size();

        trustedDomainDataManager.countTrustedDomains()
                .subscribe(dbCount -> {
                    if (dbCount == fileRecordsCount) {
                        log.info("Trusted domains already exist. Skipping initialization. DB count: {}, File count: {}", dbCount, fileRecordsCount);
                    } else {
                        if (trustedDomainsFromTrancoFile.isEmpty()) {
                            log.warn("No trusted domains found in the Tranco file. Initialization skipped.");
                        } else {
                            this.trustedDomainDataManager.truncateTrustedDomains().subscribe();
                            log.info("Loading trusted domains. DB count: {}, File count: {}", dbCount, fileRecordsCount);

                            // Normalize domains before adding to database
                            List<String> normalizedDomains = trustedDomainsFromTrancoFile.stream()
                                    .map(record -> DomainUtils.normalizeDomain(record[1]))
                                    .toList();

                            this.trustedDomainDataManager.addTrustedDomain(normalizedDomains);
                        }
                    }
                });
    }

    /**
     * Checks a single domain for typosquatting against trusted domains.
     * 
     * @param domainName The domain name to check
     * @return A Mono containing the validation results
     */
    public Mono<DomainTyposquattingValidationResults> checkDomainForTypoSquatting(String domainName) {
        // Normalize the domain name
        String normalizedDomain = DomainUtils.normalizeDomain(domainName);

        // Get trusted domains with the same TLD
        Flux<TrustedDomain> trustedDomains = trustedDomainDataManager.getTrustedDomainsByTLD(
                DomainUtils.extractTLDFromDomain(normalizedDomain));

        // Check for the exact match first
        return trustedDomains
                .filter(storedDomain -> storedDomain.getDomainName().equalsIgnoreCase(normalizedDomain))
                .next()
                .flatMap(exactMatch -> {
                    log.info("Exact match found for domain: {}", normalizedDomain);
                    // No typo-squatting if an exact match is found
                    return Mono.just(new DomainTyposquattingValidationResults(
                            false,
                            domainName,
                            exactMatch.getDomainName(),
                            0,
                            false,
                            null,
                            null
                    ));
                })
                .switchIfEmpty(
                    // If no exact match, check for typosquatting using edit distance and phonetic matching
                    checkForTyposquattingAndPhoneticMatches(normalizedDomain, trustedDomains)
                );
    }

    /**
     * Checks multiple domains for typosquatting in parallel.
     * 
     * @param domainNames List of domain names to check
     * @return A Flux of validation results
     */
    public Flux<DomainTyposquattingValidationResults> checkDomainsForTypoSquattingInParallel(List<String> domainNames) {
        if (!threatDetectionConfig.isEnableParallelProcessing()) {
            // If parallel processing is disabled, process sequentially
            return Flux.fromIterable(domainNames)
                    .flatMap(this::checkDomainForTypoSquatting);
        }

        // Process in parallel using the configured thread pool
        return Flux.fromIterable(domainNames)
                .parallel(threatDetectionConfig.getMaxThreads())
                .runOn(Schedulers.fromExecutor(executor))
                .flatMap(this::checkDomainForTypoSquatting)
                .sequential();
    }

    /**
     * Checks for typosquatting and phonetic matches against trusted domains.
     * 
     * @param normalizedDomain The normalized domain name to check
     * @param trustedDomains Flux of trusted domains to check against
     * @return A Mono containing the validation results
     */
    private Mono<DomainTyposquattingValidationResults> checkForTyposquattingAndPhoneticMatches(
            String normalizedDomain, Flux<TrustedDomain> trustedDomains) {

        return trustedDomains.collectList()
                .flatMap(domains -> {
                    // Check for edit distance matches
                    TrustedDomain closestEditMatch = null;
                    int minEditDistance = Integer.MAX_VALUE;

                    // Check for phonetic matches if enabled
                    TrustedDomain phoneticMatch = null;
                    String phoneticMatchType = null;

                    for (TrustedDomain domain : domains) {
                        // Check edit distance using bounded edit distance for performance
                        int editDistance = EditDistanceUtil.calculateBoundedEditDistance(
                                normalizedDomain, domain.getDomainName(), EDIT_DISTANCE_THRESHOLD);

                        if (editDistance <= EDIT_DISTANCE_THRESHOLD && editDistance < minEditDistance) {
                            minEditDistance = editDistance;
                            closestEditMatch = domain;
                        }

                        // Check phonetic matching if enabled and no edit distance match found yet
                        if (threatDetectionConfig.isEnablePhoneticMatching() && phoneticMatch == null) {
                            if (threatDetectionConfig.isEnableSoundex() && 
                                    PhoneticMatchingUtil.areSimilarSoundex(normalizedDomain, domain.getDomainName())) {
                                phoneticMatch = domain;
                                phoneticMatchType = "SOUNDEX";
                            } else if (threatDetectionConfig.isEnableMetaphone() && 
                                    PhoneticMatchingUtil.areSimilarMetaphone(normalizedDomain, domain.getDomainName())) {
                                phoneticMatch = domain;
                                phoneticMatchType = "METAPHONE";
                            } else if (threatDetectionConfig.isEnableDoubleMetaphone() && 
                                    PhoneticMatchingUtil.areSimilarDoubleMetaphone(normalizedDomain, domain.getDomainName())) {
                                phoneticMatch = domain;
                                phoneticMatchType = "DOUBLE_METAPHONE";
                            }
                        }
                    }

                    // Prioritize edit distance matches over phonetic matches
                    if (closestEditMatch != null) {
                        log.info("Typo-squatting detected for domain: {} with edit distance: {} to domain: {}", 
                                normalizedDomain, minEditDistance, closestEditMatch.getDomainName());

                        return Mono.just(new DomainTyposquattingValidationResults(
                                true,
                                normalizedDomain,
                                closestEditMatch.getDomainName(),
                                minEditDistance,
                                phoneticMatch != null,
                                phoneticMatch != null ? phoneticMatch.getDomainName() : null,
                                phoneticMatchType
                        ));
                    } else if (phoneticMatch != null) {
                        // If no edit distance match but phonetic match found
                        log.info("Phonetic match detected for domain: {} using {}, matching domain: {}", 
                                normalizedDomain, phoneticMatchType, phoneticMatch.getDomainName());

                        return Mono.just(new DomainTyposquattingValidationResults(
                                true,
                                normalizedDomain,
                                null,
                                null,
                                true,
                                phoneticMatch.getDomainName(),
                                phoneticMatchType
                        ));
                    } else {
                        // No matches found
                        return Mono.just(new DomainTyposquattingValidationResults(
                                false,
                                normalizedDomain,
                                null,
                                null,
                                false,
                                null,
                                null
                        ));
                    }
                });
    }
}

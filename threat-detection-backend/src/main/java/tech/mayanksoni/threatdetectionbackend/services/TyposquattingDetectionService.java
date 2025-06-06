package tech.mayanksoni.threatdetectionbackend.services;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.configuration.ThreatDetectionConfig;
import tech.mayanksoni.threatdetectionbackend.dm.TrustedDomainDataManager;
import tech.mayanksoni.threatdetectionbackend.models.DomainTyposquattingValidationResults;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;
import tech.mayanksoni.threatdetectionbackend.utils.DomainUtils;
import tech.mayanksoni.threatdetectionbackend.utils.EditDistanceUtil;
import tech.mayanksoni.threatdetectionbackend.utils.ThreatIntelFileSystemUtils;

import java.nio.file.Paths;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class TyposquattingDetectionService {
    private final TrustedDomainDataManager trustedDomainDataManager;
    private final ThreatDetectionConfig threatDetectionConfig;
    private int EDIT_DISTANCE_THRESHOLD;

    @PostConstruct
    public void performPostInitialization() {
        this.EDIT_DISTANCE_THRESHOLD = threatDetectionConfig.getEditDistanceThreshold();
        log.info("TyposquattingDetectionService initialized with EDIT_DISTANCE_THRESHOLD: {}", EDIT_DISTANCE_THRESHOLD);
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
                            this.trustedDomainDataManager.addTrustedDomain(trustedDomainsFromTrancoFile.stream().map(record -> record[1]).toList());
                        }
                    }
                });
    }
    public Mono<DomainTyposquattingValidationResults> checkDomainForTypoSquatting(String domainName) {
        Flux<TrustedDomain> trustedDomains = trustedDomainDataManager.getTrustedDomainsByTLD(DomainUtils.extractTLDFromDomain(domainName));

        // Check for exact match first
        return trustedDomains
                .filter(storedDomain -> storedDomain.getDomainName().equalsIgnoreCase(domainName))
                .next()
                .flatMap(exactMatch -> {
                    log.info("Exact match found for domain: {}", domainName);
                    // No typo-squatting if an exact match is found
                    return Mono.just(new DomainTyposquattingValidationResults(
                            false,
                            domainName,
                            exactMatch.getDomainName() + "." + exactMatch.getTld(),
                            0
                    ));
                })
                .switchIfEmpty(
                    // If no exact match, check for typosquatting
                    trustedDomains
                        .flatMap(storedDomain -> {
                            int editDistance = EditDistanceUtil.calculateEditDistance(domainName, storedDomain.getDomainName());
                            return Mono.just(new Object[] {storedDomain, editDistance});
                        })
                        .filter(result -> (int)result[1] <= EDIT_DISTANCE_THRESHOLD)
                        .next()
                        .flatMap(result -> {
                            TrustedDomain closestDomain = (TrustedDomain)result[0];
                            int editDistance = (int)result[1];
                            String closestDomainName = closestDomain.getDomainName() + "." + closestDomain.getTld();
                            log.info("Typo-squatting detected for domain: {} with edit distance: {} to domain: {}", 
                                    domainName, editDistance, closestDomainName);
                            return Mono.just(new DomainTyposquattingValidationResults(
                                    true,
                                    domainName,
                                    closestDomainName,
                                    editDistance
                            ));
                        })
                        .switchIfEmpty(Mono.just(new DomainTyposquattingValidationResults(
                                false,
                                domainName,
                                null,
                                null
                        )))
                );
    }
}

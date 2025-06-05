package tech.mayanksoni.threatdetectionbackend.services;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.configuration.ThreatDetectionConfig;
import tech.mayanksoni.threatdetectionbackend.dm.TrustedDomainDataManager;
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
                            log.info("Loading trusted domains. DB count: {}, File count: {}", dbCount, fileRecordsCount);
                            this.trustedDomainDataManager.addTrustedDomain(trustedDomainsFromTrancoFile.stream().map(record -> record[1]).toList());
                        }
                    }
                });
    }
    public Mono<Boolean> checkDomainForTypoSquatting(String domainName) {
        Flux<TrustedDomain> trustedDomains = trustedDomainDataManager.getTrustedDomainsByTLD(DomainUtils.extractTLDFromDomain(domainName));
        Mono<Boolean> exactMatchExists = trustedDomains.filter(storedDomain -> storedDomain.getDomainName().equalsIgnoreCase(domainName)).next().flatMap(exactMatch -> {
            log.info("Exact match found for domain: {}", domainName);
            return Mono.just(false); // No typo-squatting if an exact match is found
        }).switchIfEmpty(Mono.just(false));
        return exactMatchExists.flatMap(isExactMatch -> {
            if (isExactMatch) {
                log.info("Exact match exists for domain: {}, no typo-squatting detected.", domainName);
                return Mono.just(false); // If an exact match exists, no typo-squatting
            }
            return trustedDomains
                    .map(storedDomain -> EditDistanceUtil.calculateEditDistance(domainName, storedDomain.getDomainName()))
                    .filter(editDistance -> editDistance <= EDIT_DISTANCE_THRESHOLD)
                    .next()
                    .flatMap(editDistance -> {
                        log.info("Typo-squatting detected for domain: {} with edit distance: {}", domainName, editDistance);
                        return Mono.just(true);
                    })
                    .switchIfEmpty(Mono.just(false));
        });
    }
}

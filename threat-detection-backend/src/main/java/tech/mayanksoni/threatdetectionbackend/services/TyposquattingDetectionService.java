package tech.mayanksoni.threatdetectionbackend.services;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.dm.TrustedDomainDataManager;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;
import tech.mayanksoni.threatdetectionbackend.utils.DomainUtils;
import tech.mayanksoni.threatdetectionbackend.utils.EditDistanceUtil;

@Service
@Slf4j
@RequiredArgsConstructor
public class TyposquattingDetectionService {
    private final TrustedDomainDataManager trustedDomainDataManager;
    private static final Integer EDIT_DISTANCE_THRESHOLD = 2;

    public Mono<Boolean> checkDomainForTypoSquatting(String domainName) {
        Flux<TrustedDomain> trustedDomains = trustedDomainDataManager.getTrustedDomainsByTLD(DomainUtils.extractTLDFromDomain(domainName));
        Mono<Boolean> exactMatchExists = trustedDomains.filter(storedDomain -> storedDomain.getDomainName().equalsIgnoreCase(domainName)).next().flatMap(exactMatch -> {
            log.info("Exact match found for domain: {}", domainName);
            return Mono.just(false); // No typo-squatting if an exact match is found
        }).switchIfEmpty(Mono.just(false));
        return exactMatchExists.flatMap(isExactMatch -> {
            if (isExactMatch) {
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

package tech.mayanksoni.threatdetectionbackend.processor;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.models.DomainTyposquattingValidationResults;
import tech.mayanksoni.threatdetectionbackend.services.TyposquattingDetectionService;

@Service
@Slf4j
@RequiredArgsConstructor
public class DomainCheckProcessor {
    private final TyposquattingDetectionService typosquattingDetectionService;

    public Mono<DomainTyposquattingValidationResults> checkDomain(String domainName){
        log.info("Checking domain for typosquatting: {}", domainName);
        return typosquattingDetectionService.checkDomainForTypoSquatting(domainName)
                .map(isTyposquatted -> new DomainTyposquattingValidationResults(isTyposquatted, domainName));
    }
}

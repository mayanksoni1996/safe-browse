package tech.mayanksoni.threatdetectionbackend.processor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tech.mayanksoni.threatdetectionbackend.models.DomainTyposquattingValidationResults;
import tech.mayanksoni.threatdetectionbackend.services.TyposquattingDetectionService;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DomainCheckProcessorTest {

    @Mock
    private TyposquattingDetectionService typosquattingDetectionService;

    @InjectMocks
    private DomainCheckProcessor domainCheckProcessor;

    @Test
    void checkDomain_shouldReturnMonoWithResults() {
        // Given
        String domainName = "example.com";
        boolean isTyposquatted = true;
        String closestMatchingDomain = "exampie.com";
        int editDistance = 1;

        DomainTyposquattingValidationResults mockResults = new DomainTyposquattingValidationResults(
                isTyposquatted, domainName, closestMatchingDomain, editDistance);

        when(typosquattingDetectionService.checkDomainForTypoSquatting(domainName))
                .thenReturn(Mono.just(mockResults));

        // When
        Mono<DomainTyposquattingValidationResults> result = domainCheckProcessor.checkDomain(domainName);

        // Then
        StepVerifier.create(result)
                .expectNextMatches(validationResults -> 
                        validationResults.isTyposquatted() == isTyposquatted && 
                        validationResults.domainName().equals(domainName) &&
                        validationResults.closestMatchingDomain().equals(closestMatchingDomain) &&
                        validationResults.editDistance() == editDistance)
                .verifyComplete();
    }

    @Test
    void checkDomain_shouldHandleEmptyMono() {
        // Given
        String domainName = "example.com";

        when(typosquattingDetectionService.checkDomainForTypoSquatting(domainName))
                .thenReturn(Mono.empty());

        // When
        Mono<DomainTyposquattingValidationResults> result = domainCheckProcessor.checkDomain(domainName);

        // Then
        StepVerifier.create(result)
                .verifyComplete();
    }
}

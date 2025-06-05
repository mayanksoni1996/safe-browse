package tech.mayanksoni.threatdetectionbackend.models;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Results of domain typosquatting validation")
public record DomainTyposquattingValidationResults(
        @Schema(description = "Indicates if the domain is potentially a typosquatting attempt", example = "true")
        boolean isTyposquatted,

        @Schema(description = "The domain name that was validated", example = "example.com")
        String domainName
) {
}

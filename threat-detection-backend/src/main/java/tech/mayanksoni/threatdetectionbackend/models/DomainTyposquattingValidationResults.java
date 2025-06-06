package tech.mayanksoni.threatdetectionbackend.models;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Results of domain typosquatting validation")
public record DomainTyposquattingValidationResults(
        @Schema(description = "Indicates if the domain is potentially a typosquatting attempt", example = "true")
        boolean isTyposquatted,

        @Schema(description = "The domain name that was validated", example = "example.com")
        String domainName,

        @Schema(description = "The closest matching trusted domain, if typosquatting is detected", example = "example.com")
        String closestMatchingDomain,

        @Schema(description = "The edit distance to the closest matching domain", example = "1")
        Integer editDistance,

        @Schema(description = "Indicates if the domain sounds similar to a trusted domain", example = "true")
        Boolean isPhoneticMatch,

        @Schema(description = "The phonetically matching trusted domain, if any", example = "example.com")
        String phoneticMatchingDomain,

        @Schema(description = "The type of phonetic algorithm that matched (SOUNDEX, METAPHONE, DOUBLE_METAPHONE)", example = "SOUNDEX")
        String phoneticMatchType
) {
    // Constructor with original parameters for backward compatibility
    public DomainTyposquattingValidationResults(boolean isTyposquatted, String domainName, 
                                               String closestMatchingDomain, Integer editDistance) {
        this(isTyposquatted, domainName, closestMatchingDomain, editDistance, null, null, null);
    }
}

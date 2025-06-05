package tech.mayanksoni.threatdetectionbackend.models;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Schema(description = "Represents a trusted domain that is used as a reference for typosquatting detection")
public class TrustedDomain {
    @Schema(description = "Unique identifier for the trusted domain", example = "60c72b2b5e7c2a1234567890")
    private String id;

    @Schema(description = "The name of the trusted domain", example = "example")
    private String domainName;

    @Schema(description = "The top-level domain (TLD) of the trusted domain", example = "com")
    private String tld;
}

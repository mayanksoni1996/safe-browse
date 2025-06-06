package tech.mayanksoni.threatdetectionbackend.controller.v1;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.ArraySchema;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.models.DomainTyposquattingValidationResults;
import tech.mayanksoni.threatdetectionbackend.processor.DomainCheckProcessor;

import java.util.List;

/**
 * Controller for domain validation endpoints.
 */
@RestController
@RequestMapping("/api/v1/check-domain")
@RequiredArgsConstructor
@Tag(name = "Domain Validation", description = "API for validating domains against typosquatting and other threats")
public class CheckDomainController {
    private final DomainCheckProcessor domainCheckProcessor;

    /**
     * Validates a single domain for typosquatting.
     */
    @Operation(
            summary = "Validate domain for typosquatting",
            description = "Checks if a domain is potentially a typosquatting attempt against trusted domains"
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Domain validation completed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = DomainTyposquattingValidationResults.class)
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid domain name format",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content
            )
    })
    @GetMapping
    public Mono<DomainTyposquattingValidationResults> validateDomainForTyposquatting(
            @Parameter(description = "Domain name to validate", required = true)
            @RequestParam String domainName) {
        return domainCheckProcessor.checkDomain(domainName);
    }

    /**
     * Validates multiple domains for typosquatting in a batch.
     * This endpoint supports parallel processing for efficient handling of large batches.
     */
    @Operation(
            summary = "Validate multiple domains for typosquatting",
            description = "Checks if multiple domains are potentially typosquatting attempts against trusted domains. " +
                    "Processing is done in parallel for better performance with large batches."
    )
    @ApiResponses(value = {
            @ApiResponse(
                    responseCode = "200",
                    description = "Batch domain validation completed successfully",
                    content = @Content(
                            mediaType = "application/json",
                            array = @ArraySchema(schema = @Schema(implementation = DomainTyposquattingValidationResults.class))
                    )
            ),
            @ApiResponse(
                    responseCode = "400",
                    description = "Invalid request format",
                    content = @Content
            ),
            @ApiResponse(
                    responseCode = "500",
                    description = "Internal server error",
                    content = @Content
            )
    })
    @PostMapping("/batch")
    public Flux<DomainTyposquattingValidationResults> validateDomainsForTyposquattingBatch(
            @Parameter(description = "List of domain names to validate", required = true)
            @RequestBody List<String> domainNames) {
        return domainCheckProcessor.checkDomains(domainNames);
    }
}

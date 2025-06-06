package tech.mayanksoni.threatdetectionbackend.controller.v1;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.models.DomainTyposquattingValidationResults;
import tech.mayanksoni.threatdetectionbackend.processor.DomainCheckProcessor;

@RestController
@RequestMapping("/api/v1/check-domain")
@RequiredArgsConstructor
@Tag(name = "Domain Validation", description = "API for validating domains against typosquatting and other threats")
public class CheckDomainController {
    private final DomainCheckProcessor domainCheckProcessor;

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
}

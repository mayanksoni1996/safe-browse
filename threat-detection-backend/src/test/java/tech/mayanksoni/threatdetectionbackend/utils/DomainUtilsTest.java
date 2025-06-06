package tech.mayanksoni.threatdetectionbackend.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the DomainUtils class.
 */
class DomainUtilsTest {

    @ParameterizedTest
    @CsvSource({
        "example.com, com",
        "sub.example.com, example.com",
        "deep.sub.example.com, example.com",
        "example.co.uk, co.uk",
        "sub.example.co.uk, example.co.uk",
        "invalid, ''"
    })
    void extractTLDFromDomain_shouldExtractCorrectTLD(String domain, String expectedTLD) {
        // When
        String tld = DomainUtils.extractTLDFromDomain(domain);
        
        // Then
        assertEquals(expectedTLD, tld);
    }
    
    @ParameterizedTest
    @CsvSource({
        "example.com, example.com",
        "EXAMPLE.COM, example.com",
        "ExAmPlE.CoM, example.com",
        "www.example.com, example.com",
        "WWW.EXAMPLE.COM, example.com",
        "www.EXAMPLE.com, example.com",
        "http://example.com, http://example.com",  // URL schemes are not handled by normalization
        "xn--bcher-kva.example, xn--bcher-kva.example"  // IDN domains are preserved
    })
    void normalizeDomain_shouldNormalizeDomainCorrectly(String domain, String expectedNormalized) {
        // When
        String normalized = DomainUtils.normalizeDomain(domain);
        
        // Then
        assertEquals(expectedNormalized, normalized);
    }
    
    @Test
    void normalizeDomain_shouldHandleNullAndEmptyDomains() {
        // When & Then
        assertNull(DomainUtils.normalizeDomain(null));
        assertEquals("", DomainUtils.normalizeDomain(""));
    }
    
    @ParameterizedTest
    @CsvSource({
        "example.com, example",
        "www.example.com, example",
        "sub.example.com, example",
        "example.co.uk, example",
        "sub.example.co.uk, example",
        "invalid, invalid"
    })
    void extractSLD_shouldExtractCorrectSLD(String domain, String expectedSLD) {
        // When
        String sld = DomainUtils.extractSLD(domain);
        
        // Then
        assertEquals(expectedSLD, sld);
    }
    
    @Test
    void extractSLD_shouldHandleNormalization() {
        // Given
        String domain1 = "WWW.EXAMPLE.COM";
        String domain2 = "www.example.co.uk";
        
        // When
        String sld1 = DomainUtils.extractSLD(domain1);
        String sld2 = DomainUtils.extractSLD(domain2);
        
        // Then
        assertEquals("example", sld1);
        assertEquals("example", sld2);
    }
    
    @Test
    void domainNormalization_shouldBeIdempotent() {
        // Given
        String domain = "WWW.EXAMPLE.COM";
        
        // When
        String normalized1 = DomainUtils.normalizeDomain(domain);
        String normalized2 = DomainUtils.normalizeDomain(normalized1);
        
        // Then
        assertEquals(normalized1, normalized2, "Normalizing an already normalized domain should not change it");
    }
}
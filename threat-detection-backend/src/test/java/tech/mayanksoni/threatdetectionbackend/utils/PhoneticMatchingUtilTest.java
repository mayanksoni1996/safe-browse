package tech.mayanksoni.threatdetectionbackend.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the PhoneticMatchingUtil class.
 */
class PhoneticMatchingUtilTest {

    @Test
    void getSoundexCode_shouldReturnSoundexCode() {
        // Given
        String domain = "example.com";
        
        // When
        String soundexCode = PhoneticMatchingUtil.getSoundexCode(domain);
        
        // Then
        assertNotNull(soundexCode);
        assertEquals("E251", soundexCode);
    }
    
    @Test
    void getMetaphoneCode_shouldReturnMetaphoneCode() {
        // Given
        String domain = "example.com";
        
        // When
        String metaphoneCode = PhoneticMatchingUtil.getMetaphoneCode(domain);
        
        // Then
        assertNotNull(metaphoneCode);
        assertEquals("EKSM", metaphoneCode);
    }
    
    @Test
    void getDoubleMetaphoneCode_shouldReturnDoubleMetaphoneCode() {
        // Given
        String domain = "example.com";
        
        // When
        String doubleMetaphoneCode = PhoneticMatchingUtil.getDoubleMetaphoneCode(domain);
        
        // Then
        assertNotNull(doubleMetaphoneCode);
        assertEquals("AKSMPL", doubleMetaphoneCode);
    }
    
    @ParameterizedTest
    @CsvSource({
        "example.com, exampel.com, true",
        "example.com, egzample.com, true",
        "example.com, completely-different.com, false"
    })
    void areSimilarSoundex_shouldDetectSimilarSoundingDomains(String domain1, String domain2, boolean expected) {
        // When
        boolean result = PhoneticMatchingUtil.areSimilarSoundex(domain1, domain2);
        
        // Then
        assertEquals(expected, result);
    }
    
    @ParameterizedTest
    @CsvSource({
        "example.com, exampel.com, true",
        "example.com, egzample.com, true",
        "example.com, completely-different.com, false"
    })
    void areSimilarMetaphone_shouldDetectSimilarSoundingDomains(String domain1, String domain2, boolean expected) {
        // When
        boolean result = PhoneticMatchingUtil.areSimilarMetaphone(domain1, domain2);
        
        // Then
        assertEquals(expected, result);
    }
    
    @ParameterizedTest
    @CsvSource({
        "example.com, exampel.com, true",
        "example.com, egzample.com, true",
        "example.com, completely-different.com, false"
    })
    void areSimilarDoubleMetaphone_shouldDetectSimilarSoundingDomains(String domain1, String domain2, boolean expected) {
        // When
        boolean result = PhoneticMatchingUtil.areSimilarDoubleMetaphone(domain1, domain2);
        
        // Then
        assertEquals(expected, result);
    }
    
    @ParameterizedTest
    @CsvSource({
        "example.com, exampel.com, true",
        "example.com, egzample.com, true",
        "example.com, completely-different.com, false",
        "google.com, googel.com, true",
        "microsoft.com, mikrosoft.com, true",
        "facebook.com, phasebook.com, true"
    })
    void areSimilarPhonetically_shouldDetectSimilarSoundingDomains(String domain1, String domain2, boolean expected) {
        // When
        boolean result = PhoneticMatchingUtil.areSimilarPhonetically(domain1, domain2);
        
        // Then
        assertEquals(expected, result);
    }
    
    @Test
    void extractSLD_shouldWorkWithPhoneticMatching() {
        // Given
        String domain1 = "www.example.com";
        String domain2 = "example.co.uk";
        
        // When
        String sld1 = DomainUtils.extractSLD(domain1);
        String sld2 = DomainUtils.extractSLD(domain2);
        
        // Then
        assertEquals("example", sld1);
        assertEquals("example", sld2);
        
        // Verify phonetic matching works with SLDs
        assertTrue(PhoneticMatchingUtil.areSimilarPhonetically(sld1, sld2));
    }
}
package tech.mayanksoni.threatdetectionbackend.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the EditDistanceUtil class.
 */
class EditDistanceUtilTest {

    @ParameterizedTest
    @CsvSource({
        "example.com, example.com, 0",
        "example.com, exampel.com, 2",  // Transposition
        "example.com, exampl.com, 1",   // Deletion
        "example.com, exampleee.com, 2", // Insertion
        "example.com, ezample.com, 1",   // Substitution
        "google.com, googel.com, 2",     // Transposition
        "microsoft.com, microsft.com, 2" // Deletion
    })
    void calculateEditDistance_shouldReturnCorrectDistance(String domain1, String domain2, int expectedDistance) {
        // When
        int distance = EditDistanceUtil.calculateEditDistance(domain1, domain2);
        
        // Then
        assertEquals(expectedDistance, distance);
    }
    
    @Test
    void calculateEditDistance_shouldHandleNormalization() {
        // Given
        String domain1 = "Example.com";
        String domain2 = "example.com";
        
        // When
        int distance = EditDistanceUtil.calculateEditDistance(domain1, domain2);
        
        // Then
        assertEquals(0, distance, "Domains that differ only in case should have distance 0 after normalization");
    }
    
    @Test
    void calculateEditDistance_shouldHandleWwwPrefix() {
        // Given
        String domain1 = "www.example.com";
        String domain2 = "example.com";
        
        // When
        int distance = EditDistanceUtil.calculateEditDistance(domain1, domain2);
        
        // Then
        assertEquals(0, distance, "Domains that differ only by www prefix should have distance 0 after normalization");
    }
    
    @ParameterizedTest
    @CsvSource({
        "example.com, example.com, 2, 0",
        "example.com, exampel.com, 2, 2",
        "example.com, exampel.com, 1, 2",  // Exceeds threshold
        "example.com, completelydifferent.com, 5, 6"  // Exceeds threshold
    })
    void calculateBoundedEditDistance_shouldRespectThreshold(String domain1, String domain2, int threshold, int expectedResult) {
        // When
        int distance = EditDistanceUtil.calculateBoundedEditDistance(domain1, domain2, threshold);
        
        // Then
        assertEquals(expectedResult, distance);
    }
    
    @Test
    void calculateBoundedEditDistance_shouldReturnEarlyForLengthDifference() {
        // Given
        String domain1 = "example.com";
        String domain2 = "exampleverylongdomain.com";
        int threshold = 5;
        
        // When
        int distance = EditDistanceUtil.calculateBoundedEditDistance(domain1, domain2, threshold);
        
        // Then
        assertEquals(threshold + 1, distance, 
                "Should return threshold+1 when length difference exceeds threshold");
    }
    
    @Test
    void calculateBoundedEditDistance_shouldBeMoreEfficientThanStandard() {
        // Given
        String domain1 = "averylongdomainnamethatwouldtakealotoftimetocompare.com";
        String domain2 = "anotherlongdomainnamethatisdifferentandwouldtaketime.com";
        int threshold = 5;
        
        // When - measure time for bounded version
        long startBounded = System.nanoTime();
        int boundedDistance = EditDistanceUtil.calculateBoundedEditDistance(domain1, domain2, threshold);
        long endBounded = System.nanoTime();
        long boundedTime = endBounded - startBounded;
        
        // When - measure time for standard version
        long startStandard = System.nanoTime();
        int standardDistance = EditDistanceUtil.calculateEditDistance(domain1, domain2);
        long endStandard = System.nanoTime();
        long standardTime = endStandard - startStandard;
        
        // Then
        assertEquals(threshold + 1, boundedDistance, 
                "Bounded distance should return threshold+1 for very different strings");
        assertTrue(boundedTime < standardTime, 
                "Bounded version should be faster than standard version for very different strings");
        
        System.out.println("[DEBUG_LOG] Bounded time: " + boundedTime + "ns, Standard time: " + standardTime + "ns");
    }
    
    @Test
    void calculateEditDistance_shouldHandleTranspositions() {
        // Given
        String domain1 = "example.com";
        String domain2 = "exapmle.com";  // Transposition of 'm' and 'p'
        
        // When
        int distance = EditDistanceUtil.calculateEditDistance(domain1, domain2);
        
        // Then
        assertEquals(1, distance, "Transposition should be counted as a single edit operation");
    }
}
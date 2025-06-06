package tech.mayanksoni.threatdetectionbackend.utils;

import org.apache.commons.codec.language.Soundex;
import org.apache.commons.codec.language.DoubleMetaphone;
import org.apache.commons.codec.language.Metaphone;
import org.springframework.stereotype.Component;

/**
 * Utility class for phonetic matching of domain names.
 * This helps detect typosquatting attempts that sound similar to legitimate domains.
 */
public class PhoneticMatchingUtil {
    
    private static final Soundex SOUNDEX = new Soundex();
    private static final DoubleMetaphone DOUBLE_METAPHONE = new DoubleMetaphone();
    private static final Metaphone METAPHONE = new Metaphone();
    
    /**
     * Calculates the Soundex code for a domain name.
     * Soundex is a phonetic algorithm for indexing names by sound, as pronounced in English.
     * 
     * @param domain The domain name to encode
     * @return The Soundex code
     */
    public static String getSoundexCode(String domain) {
        // Extract the second-level domain for better matching
        String sld = DomainUtils.extractSLD(domain);
        try {
            return SOUNDEX.encode(sld);
        } catch (Exception e) {
            // If encoding fails, return the original SLD
            return sld;
        }
    }
    
    /**
     * Calculates the Metaphone code for a domain name.
     * Metaphone is a phonetic algorithm for indexing words by their English pronunciation.
     * 
     * @param domain The domain name to encode
     * @return The Metaphone code
     */
    public static String getMetaphoneCode(String domain) {
        // Extract the second-level domain for better matching
        String sld = DomainUtils.extractSLD(domain);
        try {
            return METAPHONE.encode(sld);
        } catch (Exception e) {
            // If encoding fails, return the original SLD
            return sld;
        }
    }
    
    /**
     * Calculates the Double Metaphone code for a domain name.
     * Double Metaphone is an improved version of the Metaphone algorithm.
     * 
     * @param domain The domain name to encode
     * @return The primary Double Metaphone code
     */
    public static String getDoubleMetaphoneCode(String domain) {
        // Extract the second-level domain for better matching
        String sld = DomainUtils.extractSLD(domain);
        try {
            return DOUBLE_METAPHONE.encode(sld);
        } catch (Exception e) {
            // If encoding fails, return the original SLD
            return sld;
        }
    }
    
    /**
     * Checks if two domain names sound similar using Soundex.
     * 
     * @param domain1 The first domain name
     * @param domain2 The second domain name
     * @return true if the domains sound similar, false otherwise
     */
    public static boolean areSimilarSoundex(String domain1, String domain2) {
        return getSoundexCode(domain1).equals(getSoundexCode(domain2));
    }
    
    /**
     * Checks if two domain names sound similar using Metaphone.
     * 
     * @param domain1 The first domain name
     * @param domain2 The second domain name
     * @return true if the domains sound similar, false otherwise
     */
    public static boolean areSimilarMetaphone(String domain1, String domain2) {
        return getMetaphoneCode(domain1).equals(getMetaphoneCode(domain2));
    }
    
    /**
     * Checks if two domain names sound similar using Double Metaphone.
     * 
     * @param domain1 The first domain name
     * @param domain2 The second domain name
     * @return true if the domains sound similar, false otherwise
     */
    public static boolean areSimilarDoubleMetaphone(String domain1, String domain2) {
        return getDoubleMetaphoneCode(domain1).equals(getDoubleMetaphoneCode(domain2));
    }
    
    /**
     * Checks if two domain names sound similar using any of the available phonetic algorithms.
     * 
     * @param domain1 The first domain name
     * @param domain2 The second domain name
     * @return true if the domains sound similar according to any algorithm, false otherwise
     */
    public static boolean areSimilarPhonetically(String domain1, String domain2) {
        return areSimilarSoundex(domain1, domain2) || 
               areSimilarMetaphone(domain1, domain2) || 
               areSimilarDoubleMetaphone(domain1, domain2);
    }
}
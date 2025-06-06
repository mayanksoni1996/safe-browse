package tech.mayanksoni.threatdetectionbackend.utils;

import java.net.IDN;
import java.util.regex.Pattern;

public class DomainUtils {
    private static final Pattern WWW_PATTERN = Pattern.compile("^www\\.", Pattern.CASE_INSENSITIVE);

    /**
     * Extracts the TLD from a domain name.
     * For domains with more than 2 parts (e.g., example.co.uk), it returns the last two parts (co.uk)
     * For domains with 2 parts (e.g., example.com), it returns just the last part (com)
     * 
     * @param domain The domain name to extract TLD from
     * @return The TLD of the domain
     */
    public static String extractTLDFromDomain(String domain) {
        String[] parts = domain.split("\\.");
        if (parts.length < 2) {
            return ""; // Return empty string if no TLD is found
        }
        if(parts.length > 2){
            return parts[parts.length - 2] + "." + parts[parts.length - 1]; // Return the last two parts as TLD
        } else {
            return parts[parts.length - 1]; // Return the last part as TLD
        }
    }

    /**
     * Normalizes a domain name by:
     * 1. Converting to lowercase
     * 2. Removing "www." prefix
     * 3. Converting IDN (Internationalized Domain Names) to ASCII
     * 
     * @param domain The domain name to normalize
     * @return The normalized domain name
     */
    public static String normalizeDomain(String domain) {
        if (domain == null || domain.isEmpty()) {
            return domain;
        }

        // Convert to lowercase
        String normalized = domain.toLowerCase();

        // Remove "www." prefix
        normalized = WWW_PATTERN.matcher(normalized).replaceFirst("");

        // Convert IDN to ASCII
        try {
            normalized = IDN.toASCII(normalized);
        } catch (IllegalArgumentException e) {
            // If conversion fails, keep the original
        }

        return normalized;
    }

    /**
     * Extracts the second-level domain (SLD) from a domain name.
     * For example, from "www.example.com" it returns "example"
     * 
     * @param domain The domain name to extract SLD from
     * @return The SLD of the domain
     */
    public static String extractSLD(String domain) {
        String normalized = normalizeDomain(domain);
        String[] parts = normalized.split("\\.");

        if (parts.length < 2) {
            return normalized; // Return the whole domain if it doesn't have enough parts
        }

        // For domains like example.com, return "example"
        // For domains like example.co.uk, also return "example"
        return parts[parts.length - 2];
    }
}

package tech.mayanksoni.threatdetectionbackend.utils;

public class DomainUtils {
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
}

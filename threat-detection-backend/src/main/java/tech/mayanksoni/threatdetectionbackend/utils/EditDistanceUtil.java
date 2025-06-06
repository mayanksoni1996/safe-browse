package tech.mayanksoni.threatdetectionbackend.utils;

/**
 * Utility class for calculating edit distance between strings.
 * Provides methods for standard Levenshtein distance and bounded edit distance.
 */
public class EditDistanceUtil {

    /**
     * Calculates the standard Levenshtein edit distance between two strings.
     * This considers insertions, deletions, and substitutions, all with a cost of 1.
     * 
     * @param domainUnderTest The domain being tested
     * @param knownDomain The known domain to compare against
     * @return The edit distance between the two domains
     */
    public static int calculateEditDistance(String domainUnderTest, String knownDomain) {
        // Normalize domains before comparison
        String normalizedTest = DomainUtils.normalizeDomain(domainUnderTest);
        String normalizedKnown = DomainUtils.normalizeDomain(knownDomain);

        int m = normalizedTest.length();
        int n = normalizedKnown.length();
        int[][] dp = new int[m + 1][n + 1];

        // Initialize the first row and column
        for (int i = 0; i <= m; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= n; j++) {
            dp[0][j] = j;
        }

        // Fill the dp table
        for (int i = 1; i <= m; i++) {
            for (int j = 1; j <= n; j++) {
                if (normalizedTest.charAt(i - 1) == normalizedKnown.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    // Consider insertion, deletion, and substitution
                    dp[i][j] = 1 + Math.min(
                            Math.min(dp[i - 1][j],    // Deletion
                                    dp[i][j - 1]),    // Insertion
                            dp[i - 1][j - 1]          // Substitution
                    );

                    // Consider transposition (common in typos) if possible
                    if (i > 1 && j > 1 
                            && normalizedTest.charAt(i - 1) == normalizedKnown.charAt(j - 2)
                            && normalizedTest.charAt(i - 2) == normalizedKnown.charAt(j - 1)) {
                        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
                    }
                }
            }
        }

        return dp[m][n];
    }

    /**
     * Calculates the bounded Levenshtein edit distance between two strings.
     * This stops the calculation once the distance exceeds the threshold,
     * which can significantly improve performance for large strings.
     * 
     * @param domainUnderTest The domain being tested
     * @param knownDomain The known domain to compare against
     * @param threshold The maximum edit distance to consider
     * @return The edit distance if it's less than or equal to the threshold, or threshold+1 otherwise
     */
    public static int calculateBoundedEditDistance(String domainUnderTest, String knownDomain, int threshold) {
        // Normalize domains before comparison
        String normalizedTest = DomainUtils.normalizeDomain(domainUnderTest);
        String normalizedKnown = DomainUtils.normalizeDomain(knownDomain);

        int m = normalizedTest.length();
        int n = normalizedKnown.length();

        // Quick check: if the length difference is greater than the threshold,
        // the edit distance must be greater than the threshold
        if (Math.abs(m - n) > threshold) {
            return threshold + 1;
        }

        // For small thresholds, we can use a more efficient algorithm
        // that only computes a diagonal band of the dp matrix
        int[][] dp = new int[m + 1][n + 1];

        // Initialize the first row and column
        for (int i = 0; i <= m; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= n; j++) {
            dp[0][j] = j;
        }

        // Fill the dp table, but only within the threshold band
        for (int i = 1; i <= m; i++) {
            // Determine the range of j values to consider
            int start = Math.max(1, i - threshold);
            int end = Math.min(n, i + threshold);

            // If we're outside the threshold band, mark as exceeding threshold
            if (start > 1) {
                dp[i][start - 1] = threshold + 1;
            }

            for (int j = start; j <= end; j++) {
                if (normalizedTest.charAt(i - 1) == normalizedKnown.charAt(j - 1)) {
                    dp[i][j] = dp[i - 1][j - 1];
                } else {
                    dp[i][j] = 1 + Math.min(
                            Math.min(dp[i - 1][j],    // Deletion
                                    dp[i][j - 1]),    // Insertion
                            dp[i - 1][j - 1]          // Substitution
                    );

                    // Consider transposition (common in typos) if possible
                    if (i > 1 && j > 1 
                            && normalizedTest.charAt(i - 1) == normalizedKnown.charAt(j - 2)
                            && normalizedTest.charAt(i - 2) == normalizedKnown.charAt(j - 1)) {
                        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
                    }
                }

                // If all values in the current row exceed the threshold,
                // we can return early
                if (j == end && dp[i][j] > threshold) {
                    return threshold + 1;
                }
            }

            // If we're outside the threshold band, mark as exceeding threshold
            if (end < n) {
                dp[i][end + 1] = threshold + 1;
            }
        }

        return dp[m][n] <= threshold ? dp[m][n] : threshold + 1;
    }
}

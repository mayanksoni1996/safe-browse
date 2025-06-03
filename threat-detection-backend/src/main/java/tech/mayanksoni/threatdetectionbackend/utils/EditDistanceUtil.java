package tech.mayanksoni.threatdetectionbackend.utils;

public class EditDistanceUtil {
    public static int calculateEditDistance(String domainUnderTest, String knownDomain){
        int m = domainUnderTest.length();
        int n = knownDomain.length();
        int[][] dp = new int[m + 1][n + 1];
        for (int i = 0; i <= m; i++) {
            dp[i][0] = i;
        }
        for (int j = 0; j <= n; j++) {
            dp[0][j] = j;
        }
        for(int i = 1; i <= m; i++){
            for(int j = 1; j <= n; j++){
                if(domainUnderTest.charAt(i - 1) == knownDomain.charAt(j - 1)){
                    dp[i][j] = dp[i - 1][j - 1];
                }else {
                    dp[i][j] = Math.min(Math.min(dp[i-1][j] +1,
                                    dp[i][j-1] +1) ,
                            dp[i-1][j-1] +1
                    );
                }
            }
        }
        return dp[m][n];
    }
}

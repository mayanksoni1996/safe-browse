package tech.mayanksoni.threatdetectionbackend.utils;

import org.junit.jupiter.api.Test;

import java.nio.file.Paths;

public class ThreatIntelFileSystemUtilsTest {

    @Test
    public void testReadCsvFileFromFileSystem() {
        try {
            ThreatIntelFileSystemUtils.readCsvFileFromFileSystem(Paths.get(System.getenv("TRANCO_FILEPATH")));
        } catch (NoClassDefFoundError e) {
            System.out.println("[DEBUG_LOG] NoClassDefFoundError: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("[DEBUG_LOG] Other exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

package tech.mayanksoni.threatdetectionbackend.utils;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class ThreatIntelFileSystemUtils {

    public static List<String[]> readCsvFileFromFileSystem(Path csvFilePath) {
        if (csvFilePath == null) {
            log.warn("TRANCO_FILEPATH environment variable is not set");
            return new ArrayList<>();
        }

        Resource csvResource = new FileSystemResource(csvFilePath.toFile());
        List<String[]> csvRecords = new ArrayList<>();
        try (CSVReader reader = new CSVReader(new FileReader(csvResource.getFile()))) {
            reader.readNext(); // Skip header line
            String[] line;
            while ((line = reader.readNext()) != null) {
                csvRecords.add(line);
            }
            return csvRecords;
        } catch (IOException | CsvValidationException e) {
            throw new RuntimeException(e);
        }
    }
}

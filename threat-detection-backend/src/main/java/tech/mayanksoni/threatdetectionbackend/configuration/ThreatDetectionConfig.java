package tech.mayanksoni.threatdetectionbackend.configuration;

import lombok.*;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "threatdetection")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class ThreatDetectionConfig {
    private int editDistanceThreshold;
}

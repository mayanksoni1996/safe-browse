package tech.mayanksoni.threatdetectionbackend.documents;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import tech.mayanksoni.threatdetectionbackend.constants.TldMetadataCategory;
import tech.mayanksoni.threatdetectionbackend.constants.TldMetadataThreatLevel;

import java.time.Instant;

@Document
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class SuspiciousTld {
    @Id
    private String id;
    private String tld;
    private String reason;
    private TldMetadataThreatLevel threatLevel;
    private TldMetadataCategory category;
    private String source;
    private Instant creationTimestamp;
    private Instant lastUpdatedTimestamp;
}

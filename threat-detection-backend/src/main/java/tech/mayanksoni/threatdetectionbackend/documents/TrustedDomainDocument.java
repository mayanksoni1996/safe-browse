package tech.mayanksoni.threatdetectionbackend.documents;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import tech.mayanksoni.threatdetectionbackend.annotations.CreationTimestamp;

import java.time.Instant;

import java.time.Instant;

@Document
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class TrustedDomainDocument {
    @Id
    private String id;
    private String domainName;
    private String tld;
    @CreationTimestamp
    private Instant createdAt;
}

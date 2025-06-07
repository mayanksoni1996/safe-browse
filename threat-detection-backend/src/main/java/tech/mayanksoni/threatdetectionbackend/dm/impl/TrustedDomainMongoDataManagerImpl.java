package tech.mayanksoni.threatdetectionbackend.dm.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.ReactiveMongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.configuration.ThreatDetectionConfig;
import tech.mayanksoni.threatdetectionbackend.dm.TrustedDomainDataManager;
import tech.mayanksoni.threatdetectionbackend.documents.TrustedDomainDocument;
import tech.mayanksoni.threatdetectionbackend.mappers.TrustedDomainMapper;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;
import tech.mayanksoni.threatdetectionbackend.utils.DomainUtils;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Repository
@Slf4j
@RequiredArgsConstructor
public class TrustedDomainMongoDataManagerImpl implements TrustedDomainDataManager {
    private final ReactiveMongoTemplate mongoTemplate;
    private final TrustedDomainMapper TRUSTED_DOMAIN_MAPPER;
    private final ThreatDetectionConfig threatDetectionConfig;

    @Override
    public Mono<Long> countTrustedDomains() {
        return mongoTemplate.count(new Query(), TrustedDomainDocument.class)
                .doOnSuccess(count -> log.info("Counted {} trusted domains", count))
                .doOnError(e -> log.error("Error counting trusted domains: {}", e.getMessage()));
    }

    @Override
    public Mono<Void> truncateTrustedDomains() {
       return mongoTemplate.dropCollection(TrustedDomainDocument.class).doOnSuccess(success -> log.info("Truncated trusted domains"));
    }

    private TrustedDomainDocument createTrustedDomainDocument(String domainName) {
        return TrustedDomainDocument.builder()
                .domainName(domainName)
                .tld(DomainUtils.extractTLDFromDomain(domainName))
                .build();
    }

    @Override
    public void addTrustedDomain(String domainName) {
        TrustedDomainDocument trustedDomainDocument = createTrustedDomainDocument(domainName);
        mongoTemplate.save(trustedDomainDocument).subscribe();
        log.info("Added trusted domain: {}", domainName);
    }

    @Override
    public void removeTrustedDomain(String domainName) {
        Query query = Query.query(Criteria.where("tld").is(DomainUtils.extractTLDFromDomain(domainName)).and("domainName").is(domainName));
        this.mongoTemplate.remove(query, TrustedDomainDocument.class).subscribe();
        log.info("Removed trusted domain: {}", domainName);
    }

    @Override
    public void addTrustedDomain(List<String> domains) {
        int batchSize = threatDetectionConfig.getBatchSize();
        int maxThreads = threatDetectionConfig.getMaxThreads();
        boolean enableParallelProcessing = threatDetectionConfig.isEnableParallelProcessing();

        log.info("Adding trusted domains with batch size: {}, max threads: {}, parallel processing: {}", 
                batchSize, maxThreads, enableParallelProcessing);

        if (domains.isEmpty()) {
            log.info("No domains to add");
            return;
        }

        // Create batches of domains
        List<List<String>> batches = createBatches(domains, batchSize);
        log.info("Split {} domains into {} batches", domains.size(), batches.size());

        if (enableParallelProcessing && batches.size() > 1) {
            // Process batches in parallel
            ExecutorService executorService = Executors.newFixedThreadPool(
                    Math.min(maxThreads, batches.size()));

            try {
                batches.forEach(batch -> executorService.submit(() -> processBatch(batch)));
            } finally {
                executorService.shutdown();
            }
        } else {
            // Process batches sequentially
            batches.forEach(this::processBatch);
        }

        log.info("Started creating trusted domains for {} records in {} batches", 
                domains.size(), batches.size());
    }

    private List<List<String>> createBatches(List<String> domains, int batchSize) {
        return IntStream.range(0, (domains.size() + batchSize - 1) / batchSize)
                .mapToObj(i -> domains.subList(
                        i * batchSize, 
                        Math.min((i + 1) * batchSize, domains.size())))
                .collect(Collectors.toList());
    }

    private void processBatch(List<String> batch) {
        List<TrustedDomainDocument> trustedDomains = batch.stream()
                .map(this::createTrustedDomainDocument)
                .collect(Collectors.toList());

        log.info("Processing batch of {} domains", batch.size());

        this.mongoTemplate.insertAll(trustedDomains)
                .doOnComplete(() -> log.info("Successfully added batch of {} trusted domains", trustedDomains.size()))
                .doOnError(e -> log.error("Error adding batch of trusted domains: {}", e.getMessage()))
                .subscribe();
    }

    @Override
    public Flux<TrustedDomain> getTrustedDomains() {
        return mongoTemplate.findAll(TrustedDomainDocument.class).map(TRUSTED_DOMAIN_MAPPER::toModel);
    }

    @Override
    public Flux<TrustedDomain> getTrustedDomainsByTLD(String tld) {
        Query query = Query.query(Criteria.where("tld").is(tld));
        return mongoTemplate.find(query, TrustedDomainDocument.class)
                .map(TRUSTED_DOMAIN_MAPPER::toModel)
                .doOnComplete(() -> log.info("Retrieved trusted domains for TLD: {}", tld));
    }

    @Override
    public Mono<TrustedDomain> getTrustedDomainByDomainName(String domainName) {
        Query query = Query.query(Criteria.where("tld").is(DomainUtils.extractTLDFromDomain(domainName)).and("domainName").is(domainName));
        return mongoTemplate.findOne(query, TrustedDomainDocument.class)
                .map(TRUSTED_DOMAIN_MAPPER::toModel)
                .doOnSuccess(domain -> log.info("Retrieved trusted domain: {}", domainName))
                .doOnError(e -> log.error("Error retrieving trusted domain: {}", e.getMessage()));
    }

    @Override
    public Mono<Boolean> isTrustedDomain(String domainName) {
        Mono<TrustedDomain> trustedDomainMono = getTrustedDomainByDomainName(domainName);
        return trustedDomainMono.hasElement().defaultIfEmpty(false);
    }
}

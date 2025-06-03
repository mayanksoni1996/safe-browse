package tech.mayanksoni.threatdetectionbackend.dm.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.ReactiveMongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.dm.TrustedDomainDataManager;
import tech.mayanksoni.threatdetectionbackend.documents.TrustedDomainDocument;
import tech.mayanksoni.threatdetectionbackend.mappers.TrustedDomainMapper;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;
import tech.mayanksoni.threatdetectionbackend.utils.DomainUtils;

import java.util.ArrayList;
import java.util.List;

@Repository
@Slf4j
@RequiredArgsConstructor
public class TrustedDomainMongoDataManagerImpl implements TrustedDomainDataManager {
    private final ReactiveMongoTemplate mongoTemplate;
    private final TrustedDomainMapper TRUSTED_DOMAIN_MAPPER;

    @Override
    public void truncateTrustedDomains() {
        mongoTemplate.dropCollection(TrustedDomain.class).subscribe();
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

    }

    @Override
    public void addTrustedDomain(List<String> domains) {
        List<TrustedDomainDocument> trustedDomains = new ArrayList<>();
        domains.forEach(domain -> {
            TrustedDomainDocument trustedDomainDocument = createTrustedDomainDocument(domain);
            trustedDomains.add(trustedDomainDocument);
        });
        this.mongoTemplate.save(trustedDomains).doOnSuccess(s -> {
            log.info("Successfully added trusted domains: {}", trustedDomains.size());
        }).doOnError(e -> {
            log.error("Error adding trusted domains: {}", e.getMessage());
        }).subscribe();
        log.info("Started creating trusted domains for {} records", trustedDomains.size());
    }

    @Override
    public Flux<TrustedDomain> getTrustedDomains() {
        return mongoTemplate.findAll(TrustedDomain.class);
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

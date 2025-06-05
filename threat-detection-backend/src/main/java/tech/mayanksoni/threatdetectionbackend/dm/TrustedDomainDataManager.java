package tech.mayanksoni.threatdetectionbackend.dm;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;

import java.util.List;

public interface TrustedDomainDataManager {
    Mono<Long> countTrustedDomains();
    void truncateTrustedDomains();
    void addTrustedDomain(String domainName);
    void removeTrustedDomain(String domainName);
    void addTrustedDomain(List<String> domains);
    Flux<TrustedDomain> getTrustedDomains();
    Flux<TrustedDomain> getTrustedDomainsByTLD(String tld);
    Mono<TrustedDomain> getTrustedDomainByDomainName(String domainName);
    Mono<Boolean> isTrustedDomain(String domainName);

}

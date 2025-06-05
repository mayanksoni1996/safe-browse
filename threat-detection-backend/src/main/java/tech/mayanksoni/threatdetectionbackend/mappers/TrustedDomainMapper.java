package tech.mayanksoni.threatdetectionbackend.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingConstants;
import tech.mayanksoni.threatdetectionbackend.documents.TrustedDomainDocument;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface TrustedDomainMapper {
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "tld", source = "tld")
    @Mapping(source = "domainName", target = "domainName")
    TrustedDomain toModel(TrustedDomainDocument document);
}

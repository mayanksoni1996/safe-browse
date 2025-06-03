package tech.mayanksoni.threatdetectionbackend.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.MappingConstants;
import tech.mayanksoni.threatdetectionbackend.documents.TrustedDomainDocument;
import tech.mayanksoni.threatdetectionbackend.models.TrustedDomain;

@Mapper(componentModel = MappingConstants.ComponentModel.SPRING)
public interface TrustedDomainMapper {
    TrustedDomain toModel(TrustedDomainDocument document);
}

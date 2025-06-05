package tech.mayanksoni.threatdetectionbackend;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import tech.mayanksoni.threatdetectionbackend.configuration.ThreatDetectionConfig;

@SpringBootApplication
@EnableConfigurationProperties({ThreatDetectionConfig.class})
public class ThreatDetectionBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThreatDetectionBackendApplication.class, args);
    }

    @Bean
    public OpenAPI customOpenAPI(
            @Value("${springdoc.info.title}") String title,
            @Value("${springdoc.info.description}") String description,
            @Value("${springdoc.info.version}") String version,
            @Value("${springdoc.info.contact.name}") String contactName,
            @Value("${springdoc.info.contact.url}") String contactUrl,
            @Value("${springdoc.info.license.name}") String licenseName) {

        return new OpenAPI()
                .info(new Info()
                        .title(title)
                        .description(description)
                        .version(version)
                        .contact(new Contact()
                                .name(contactName)
                                .url(contactUrl))
                        .license(new License()
                                .name(licenseName)));
    }
}

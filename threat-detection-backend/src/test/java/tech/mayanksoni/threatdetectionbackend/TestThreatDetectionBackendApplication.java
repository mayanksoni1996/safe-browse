package tech.mayanksoni.threatdetectionbackend;

import org.springframework.boot.SpringApplication;

public class TestThreatDetectionBackendApplication {

    public static void main(String[] args) {
        SpringApplication.from(ThreatDetectionBackendApplication::main).with(TestcontainersConfiguration.class).run(args);
    }

}

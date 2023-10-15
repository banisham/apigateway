package com.sc.hcv.gw.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
import org.springframework.core.io.Resource;

import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;

import java.util.Map;

@Configuration
public class ServerConfig {

    @Value("${vault.url}")
    private String vaultUrl;

    @Value("${aws.region}")
    private String awsRegion;

    @Value("${tomcat.connector.schema}")
    private String tomcatConectorSchema;

    @Value("${tomcat.connector.port}")
    private int tomcatConectorPort;

    @Value("${vault.approle.role-id-path}")
    private String roleIdPath;

    @Value("${vault.approle.secret-id-path}")
    private String secretIdPath;

    @Value("${vault.retry.maxAttempts}")
    private int maxAttempts;

    @Value("${vault.retry.backoff.duration}")
    private long backoffDuration;

    private Resource keyStore;
    private String keyStorePassword;
    private Resource trustStore;
    private String trustStorePassword;

    @Bean
    public ServletWebServerFactory servletContainer() throws Exception {
        String roleId = getParameterFromSSM(roleIdPath);
        String secretId = getParameterFromSSM(secretIdPath);

        // Authenticate with Vault with retry mechanism
        String vaultToken = authenticateWithVaultWithRetry(roleId, secretId, maxAttempts);

        // Fetch secrets using the Vault token (implement as needed)

        // Set Tomcat's SSL settings
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        tomcat.addConnectorCustomizers(connector -> {
            connector.setScheme(tomcatConectorSchema);
            connector.setSecure(true);
            connector.setPort(tomcatConectorPort);

            connector.setAttribute("keyAlias", "yourKeyAlias"); // Set if you have a specific alias in keystore, otherwise remove this line
            connector.setAttribute("keystorePass", keyStorePassword);
            connector.setAttribute("keystoreFile", keyStore.getURI().toString());
            connector.setAttribute("keyPass", keyStorePassword);
            connector.setAttribute("truststorePass", trustStorePassword);
            connector.setAttribute("truststoreFile", trustStore.getURI().toString());
            connector.setAttribute("clientAuth", "true");
            connector.setAttribute("sslProtocol", "TLS");
            connector.setAttribute("SSLEnabled", true);
        });

        return tomcat;
    }

    private String authenticateWithVaultWithRetry(String roleId, String secretId, int maxAttempts) {
        RestTemplate restTemplate = new RestTemplate();
        int attempts = 0;
        while (attempts < maxAttempts) {
            try {
                Map<String, String> authRequest = Map.of("role_id", roleId, "secret_id", secretId);
                Map<String, Object> response = restTemplate.postForObject(vaultUrl + "/v1/auth/approle/login", authRequest, Map.class);
                return (String) ((Map<String, Object>) response.get("auth")).get("client_token");
            } catch (Exception e) {
                attempts++;
                if (attempts < maxAttempts) {
                    try {
                        Thread.sleep(backoffDuration);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Failed to authenticate with Vault after retries.", e);
                    }
                } else {
                    throw new RuntimeException("Failed to authenticate with Vault after retries.", e);
                }
            }
        }
        throw new RuntimeException("Failed to authenticate with Vault.");
    }

    private String getParameterFromSSM(String parameterName) {
        SsmClient ssmClient = SsmClient.builder().region(Region.of(awsRegion)).build();
        GetParameterRequest getParameterRequest = GetParameterRequest.builder()
                .name(parameterName)
                .withDecryption(true)
                .build();
        return ssmClient.getParameter(getParameterRequest).parameter().value();
    }
}


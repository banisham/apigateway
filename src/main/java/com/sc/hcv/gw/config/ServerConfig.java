package com.sc.hcv.gw.config;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.servlet.server.ServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
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

    @Value("${vault.tls.parms.kv.path}")
    private String tlsParamsKvPath;

    @Value("${vault.retry.maxAttempts}")
    private int maxAttempts;

    @Value("${vault.retry.backoff.duration}")
    private long backoffDuration;

    @Bean
    public ServletWebServerFactory servletContainer() throws Exception {
        String roleId = getParameterFromSSM(roleIdPath);
        String secretId = getParameterFromSSM(secretIdPath);

        // Authenticate with Vault with retry mechanism
        String vaultToken = authenticateWithVaultWithRetry(roleId, secretId, maxAttempts);

        // Fetch secrets using the Vault token (implement as needed)
        Map<String, Object> tlsParams = readTLSParamsFromKV(vaultToken);

        byte[] truststoreBytes = Base64.getDecoder().decode((String) tlsParams.get("truststore"));
        URI truststoreURI = byteArrayToURI(truststoreBytes, "apigw-truststore");

        byte[] keystoreBytes = Base64.getDecoder().decode((String) tlsParams.get("keystore"));
        URI keystoreURI = byteArrayToURI(keystoreBytes, "apigw-keystore");

        String truststorePassword = (String) tlsParams.get("truststorePassword");
        String keystorePassword = (String) tlsParams.get("keystorePassword");

        // Set Tomcat's SSL settings
        TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory();
        tomcat.addConnectorCustomizers(connector -> {
            connector.setScheme(tomcatConectorSchema);
            connector.setSecure(true);
            connector.setPort(tomcatConectorPort);

            connector.setAttribute("keyAlias", "yourKeyAlias"); // Set if you have a specific alias in keystore, otherwise remove this line
            connector.setAttribute("keystorePass", keystorePassword);
            connector.setAttribute("keystoreFile", keystoreURI.toString());
            connector.setAttribute("keyPass", keystorePassword);
            connector.setAttribute("truststorePass", truststorePassword);
            connector.setAttribute("truststoreFile", truststoreURI.toString());
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

    private Map<String, Object> readTLSParamsFromKV(String vaultToken){

        String VAULT_ENDPOINT = vaultUrl + tlsParamsKvPath;
        RestTemplate restTemplate = new RestTemplate();

        // SSL handling for Vault
        // Note: This is a simplistic way of accepting all certificates.
        // In a production environment, you should have a more restrictive trust strategy.
        TrustStrategy acceptingTrustStrategy = (cert, authType) -> true;
        SSLContext sslContext;
        try {
            sslContext = SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to set up SSL context", e);
        }
        CloseableHttpClient httpClient = HttpClients.custom().setSslcontext(sslContext).build();
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
        restTemplate.setRequestFactory(factory);

        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Vault-Token", vaultToken);

        HttpEntity<String> entity = new HttpEntity<>("parameters", headers);

        ResponseEntity<String> response = null;
        try {
            response = restTemplate.exchange(VAULT_ENDPOINT, HttpMethod.GET, entity, String.class);
            String responseBody = response.getBody();
            Map<String, Object> responseData = OBJECT_MAPPER.readValue(responseBody, Map.class);
            // Assuming the actual data you want is inside the "data" field of the Vault response
            return (Map<String, Object>) responseData.get("data");
        } catch (HttpStatusCodeException e) {
            throw new RuntimeException("Failed to fetch data from Vault. Status code: " + e.getStatusCode(), e);
        } catch (ResourceAccessException e) {
            // Handle connectivity issues
            throw new RuntimeException("Failed to access Vault", e);
        } catch (Exception e) {
            // Handle other exceptions
            throw new RuntimeException("Unexpected error occurred while fetching data from Vault", e);
        }
    }

    private URI byteArrayToURI(byte[] data, String tempFileName) throws IOException {
        // Create a temporary file
        Path tempFile = Files.createTempFile("resources/"+tempFileName, ".jks");

        // Write the byte array to the temporary file
        Files.write(tempFile, data);

        // Return the URI
        return tempFile.toUri();
    }
}


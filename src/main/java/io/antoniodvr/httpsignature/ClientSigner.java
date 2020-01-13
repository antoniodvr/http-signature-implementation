package io.antoniodvr.httpsignature;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import java.io.IOException;
import java.security.*;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class ClientSigner implements ClientRequestFilter {

    protected static final String DATE_HEADER_KEY = "Date";
    protected static final String DIGEST_HEADER_KEY = "Digest";
    protected static final String AUTHORIZATION_HEADER_KEY = "Authorization";

    private static final String KEY_ID = "signature-test-key";

    protected final PrivateKey privateKey;
    protected final HTTPSigner signer;

    public ClientSigner() {
        this("/client-rsa-private-key.pem");
    }

    public ClientSigner(String keyPath) {
        this.privateKey = PKCS8Reader.getKey(keyPath);
        this.signer = new HTTPSigner(getKeyId(), Algorithm.RSA_SHA256, "(request-target)", "date", "digest");
    }

    @Override
    public void filter(ClientRequestContext requestContext) throws IOException {
        addDate(requestContext);
        addDigest(requestContext);
        addSignature(requestContext);
    }

    private static void addDate(ClientRequestContext requestContext) {
        if (!requestContext.getHeaders().containsKey(DATE_HEADER_KEY)) {
            final ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
            final String dateHeaderValue = DateTimeFormatter.RFC_1123_DATE_TIME.format(now);
            requestContext.getHeaders().add(DATE_HEADER_KEY, dateHeaderValue);
        }
    }

    private static void addDigest(ClientRequestContext requestContext) {
        if (!requestContext.getHeaders().containsKey(DIGEST_HEADER_KEY)) {
            final String algorithm = "SHA-256";
            try {

                String payload = Optional.ofNullable((String) requestContext.getEntity()).orElse("");
                final byte[] digest = MessageDigest.getInstance(algorithm).digest(payload.getBytes());
                String hashedDigest = "SHA-256=" + Base64.getEncoder().encodeToString(digest);
                requestContext.getHeaders().add(DIGEST_HEADER_KEY, hashedDigest);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unable to hash the request payload. Unknown algorithm: " + algorithm, e);
            }
        }
    }

    // Method modifier is protected for test only purpose in order to override and test malformed signature
    protected void addSignature(ClientRequestContext requestContext) {
        Map<String, String> headers = new HashMap<>();
        headers.put(DATE_HEADER_KEY.toLowerCase(), (String) requestContext.getHeaders().get(DATE_HEADER_KEY).get(0));
        headers.put(DIGEST_HEADER_KEY.toLowerCase(), (String) requestContext.getHeaders().get(DIGEST_HEADER_KEY).get(0));
        signer.sign(privateKey, requestContext.getMethod(), requestContext.getUri().getPath(), headers);
        requestContext.getHeaders().add(AUTHORIZATION_HEADER_KEY, signer.getAuthorizationHeader());
    }

    // Method modifier is protected for test only purpose in order to override and test wrong keyId
    protected String getKeyId() {
        return KEY_ID;
    }
}


package io.antoniodvr.httpsignature;


import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.stream.Collectors;

public class HTTPSigner {

    private String keyId;
    private Algorithm algorithm;
    private List<String> headers;
    private String signature;

    public HTTPSigner(String keyId, Algorithm algorithm, String... headers) {
        this(keyId, algorithm, Arrays.asList(headers));
    }

    public HTTPSigner(String keyId, Algorithm algorithm, List<String> headers) {
        this.keyId = Optional.ofNullable(keyId).orElseThrow(() -> new IllegalArgumentException("keyId is required."));
        this.algorithm = Optional.ofNullable(algorithm).orElseThrow(() -> new IllegalArgumentException("algorithm is required."));
        this.headers = headers.isEmpty() ? Collections.unmodifiableList(Collections.singletonList("date")) : headers.stream().map(String::toLowerCase).collect(Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList));
    }

    public String sign(final PrivateKey key, final String method, final String uri, final Map<String, String> requestHeaders) {
        try {
            final String signingString = createSigningString(this.headers, method, uri, requestHeaders);
            final byte[] binarySignature = new AsymmetricSigner(key).sign(signingString.getBytes(StandardCharsets.UTF_8));
            return this.signature = Base64.getEncoder().encodeToString(binarySignature);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException("Failed to sign: ", e);
        }
    }

    private static String createSigningString(final List<String> required, String method, final String uri, Map<String, String> requestHeaders) {
        final List<String> httpRequestHeaders = new ArrayList<>(required.size());

        for (String key : required) {
            if ("(request-target)".equals(key)) {
                httpRequestHeaders.add(String.join(" ", "(request-target):", method.toLowerCase(), uri));
            } else {
                final String value = Optional.ofNullable(requestHeaders.get(key)).orElseThrow(() -> new RuntimeException("Missing required header: " + key));
                httpRequestHeaders.add(key + ": " + value);
            }
        }

        return String.join("\n", httpRequestHeaders);
    }

    public String getAuthorizationHeader() {
        return getAuthorizationHeader(signature);
    }

    public String getAuthorizationHeader(String signature) {
        return "Signature " +
                "keyId=\"" + keyId + '\"' +
                ", algorithm=\"" + algorithm.getAlgorithmName() + '\"' +
                ", headers=\"" + String.join(" ", headers) + '\"' +
                ", signature=\"" + signature + '\"';
    }

    private class AsymmetricSigner {

        private final PrivateKey key;

        private AsymmetricSigner(final PrivateKey key) {
            this.key = key;
        }

        public byte[] sign(final byte[] signingStringBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
            final Signature instance = Signature.getInstance(algorithm.getAlgorithmStandardName());
            instance.initSign(key);
            instance.update(signingStringBytes);
            return instance.sign();
        }
    }
}

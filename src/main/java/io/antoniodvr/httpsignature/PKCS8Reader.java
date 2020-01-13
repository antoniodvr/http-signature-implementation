package io.antoniodvr.httpsignature;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public final class PKCS8Reader {

    private static final String ALGORITHM = "RSA";

    private PKCS8Reader() {
    }

    public static PrivateKey getKey(String path) {
        try {
            InputStream pkcs8Is = PKCS8Reader.class.getResourceAsStream(path);
            String pkcs8 = toString(pkcs8Is);
            pkcs8 = pkcs8.replace("-----BEGIN PRIVATE KEY-----", "");
            pkcs8 = pkcs8.replace("-----END PRIVATE KEY-----", "");
            pkcs8 = pkcs8.replaceAll("\\s+", "");
            byte[] pkcs8EncodedBytes = Base64.getDecoder().decode(pkcs8);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8EncodedBytes);
            KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
            return kf.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unable to get instance of algorithm implementation: " + ALGORITHM, e);
        } catch (IOException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private static String toString(InputStream inputStream) throws IOException {
        StringBuilder builder = new StringBuilder();
        try (Reader reader = new BufferedReader(new InputStreamReader(inputStream, Charset.forName(StandardCharsets.UTF_8.name())))) {
            int c;
            while ((c = reader.read()) != -1) {
                builder.append((char) c);
            }
        }
        return builder.toString();
    }

}

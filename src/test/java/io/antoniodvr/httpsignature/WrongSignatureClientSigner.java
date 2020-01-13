package io.antoniodvr.httpsignature;

import javax.ws.rs.client.ClientRequestContext;
import java.util.HashMap;
import java.util.Map;

public class WrongSignatureClientSigner extends ClientSigner {

    @Override
    protected void addSignature(ClientRequestContext requestContext) {
        Map<String, String> headers = new HashMap<>();
        headers.put(DATE_HEADER_KEY.toLowerCase(), (String) requestContext.getHeaders().get(DATE_HEADER_KEY).get(0));
        headers.put(DIGEST_HEADER_KEY.toLowerCase(), (String) requestContext.getHeaders().get(DIGEST_HEADER_KEY).get(0));
        String signature = signer.sign(privateKey, requestContext.getMethod(), requestContext.getUri().getPath(), headers);
        requestContext.getHeaders().add(AUTHORIZATION_HEADER_KEY, signer.getAuthorizationHeader("wrong" + signature));
    }

}


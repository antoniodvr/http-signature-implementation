package io.antoniodvr.httpsignature;

public class WrongKeyIdClientSigner extends ClientSigner {

    @Override
    protected String getKeyId() {
        return "wrong-key-id";
    }

}


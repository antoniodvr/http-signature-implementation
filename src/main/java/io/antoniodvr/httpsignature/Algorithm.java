package io.antoniodvr.httpsignature;

public enum Algorithm {

    RSA_SHA256("SHA256withRSA", "rsa-sha256");

    private final String algorithmStandardName;
    private final String algorithmName;

    Algorithm(String algorithmStandardName, String algorithmName) {
        this.algorithmStandardName = algorithmStandardName;
        this.algorithmName = algorithmName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public String getAlgorithmStandardName() {
        return algorithmStandardName;
    }

}

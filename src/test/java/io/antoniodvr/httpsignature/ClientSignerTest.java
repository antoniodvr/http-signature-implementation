package io.antoniodvr.httpsignature;

import org.junit.BeforeClass;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static org.junit.Assert.*;

public class ClientSignerTest {

    private static final String ENDPOINT = "https://www.hostname.com/services/protocol/tests/signature";

    private static Invocation.Builder invocationBuilder;

    @BeforeClass
    public static void setUp() {
        invocationBuilder = ClientBuilder.newClient()
                .register(new ClientSigner())
                .target(ENDPOINT)
                .request(MediaType.APPLICATION_JSON_TYPE);
    }

    @Test
    public void shouldGETAndReturn200() {
        Response response = invocationBuilder.get();
        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldPOSTAndReturn200() {
        JsonObject payload = Json.createObjectBuilder().add("text", "Sample data").build();
        Response response = invocationBuilder.post(Entity.entity(payload.toString(), MediaType.APPLICATION_JSON_TYPE));
        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldPUTAndReturn200() {
        JsonObject payload = Json.createObjectBuilder().add("text", "Sample data").build();
        Response response = invocationBuilder.put(Entity.entity(payload.toString(), MediaType.APPLICATION_JSON_TYPE));
        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldDELETEAndReturn200() {
        Response response = invocationBuilder.delete();
        assertEquals(200, response.getStatus());
    }

    @Test
    public void shouldReturn401OnMalformedSignature() {
        Response response = ClientBuilder.newClient()
                .register(new MalformedSignatureClientSigner())
                .target(ENDPOINT)
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get();

        assertEquals(401, response.getStatus());
    }

    @Test
    public void shouldReturn401OnWrongKeyId() {
        Response response = ClientBuilder.newClient()
                .register(new WrongKeyIdClientSigner())
                .target(ENDPOINT)
                .request(MediaType.APPLICATION_JSON_TYPE)
                .get();

        assertEquals(401, response.getStatus());
    }

}

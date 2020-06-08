package fr.devnewton.selfidconnectserver.services;

import javax.annotation.PostConstruct;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private RsaJsonWebKey jwk;

    @PostConstruct
    public void initKeys() throws JoseException {
        this.jwk = RsaJwkGenerator.generateJwk(2048);
        this.jwk.setKeyId("selfid");
    }

    public boolean validate(String token) {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer("selfid") // whom the JWT needs to have been issued by
                .setExpectedAudience("everybody") // to whom the JWT is intended for
                .setVerificationKey(jwk.getKey()) // verify the signature with the public key
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        AlgorithmConstraints.ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256) // which is only RS256 here
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            jwtConsumer.processToClaims(token);
            return true;
        } catch (InvalidJwtException e) {
            System.out.println(e);
            return false;
        }
    }

    public String generate() {
        try {
            // Create the Claims, which will be the content of the JWT
            JwtClaims claims = new JwtClaims();
            claims.setIssuer("selfid");  // who creates the token and signs it
            claims.setAudience("everybody"); // to whom the token is intended to be sent
            claims.setExpirationTimeMinutesInTheFuture(30); // time when the token will expire (10 minutes from now)
            claims.setGeneratedJwtId(); // a unique identifier for the token
            claims.setIssuedAtToNow();  // when the token was issued/created (now)
            claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
            claims.setSubject("I am me"); // the subject/principal is whom the token is about

            // A JWT is a JWS and/or a JWE with JSON claims as the payload.
            // In this example it is a JWS so we create a JsonWebSignature object.
            JsonWebSignature jws = new JsonWebSignature();

            // The payload of the JWS is JSON content of the JWT Claims
            jws.setPayload(claims.toJson());

            // The JWT is signed using the private key
            jws.setKey(jwk.getPrivateKey());

            // Set the Key ID (kid) header because it's just the polite thing to do.
            // We only have one key in this example but a using a Key ID helps
            // facilitate a smooth key rollover process
            jws.setKeyIdHeaderValue(jwk.getKeyId());

            // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

            // Sign the JWS and produce the compact serialization or the complete JWT/JWS
            // representation, which is a string consisting of three dot ('.') separated
            // base64url-encoded parts in the form Header.Payload.Signature
            // If you wanted to encrypt it, you can simply set this jwt as the payload
            // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
            return jws.getCompactSerialization();
        } catch (JoseException ex) {
            System.out.println(ex);
            return null;
        }
    }

    public PublicJsonWebKey getJwk() {
        return jwk;
    }
}

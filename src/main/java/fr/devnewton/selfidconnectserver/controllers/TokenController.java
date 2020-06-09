package fr.devnewton.selfidconnectserver.controllers;

import fr.devnewton.selfidconnectserver.services.TokenService;
import org.jose4j.jwk.JsonWebKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class TokenController {

    @Autowired
    private TokenService service;

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<String> wellKnowJWKS() {
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(service.getJwk().toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    @PostMapping("/token/validate")
    public ResponseEntity<String> validate(@RequestParam(name = "token", required = true) String token) {
        if (service.validate(token)) {
            return ResponseEntity.ok().body("Token is valid");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is invalid");
        }
    }

    @PostMapping("/token/decode")
    public ResponseEntity<String> decode(@RequestParam(name = "token", required = true) String token) {
        var claims = service.decode(token);
        if (null != claims) {
            return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(claims.toJson());
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is invalid");
        }
    }

    @GetMapping("/token/generate")
    public ResponseEntity<String> generate() {
        String token = service.generate();
        if (null != token) {
            return ResponseEntity.ok().contentType(MediaType.TEXT_PLAIN).body(token);
        } else {
            return ResponseEntity.badRequest().body("Cannot generate token");
        }
    }

}

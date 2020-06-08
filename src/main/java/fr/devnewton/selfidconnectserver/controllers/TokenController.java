package fr.devnewton.selfidconnectserver.controllers;

import fr.devnewton.selfidconnectserver.services.TokenService;
import org.jose4j.jwk.JsonWebKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
    @ResponseBody
    public String wellKnowJWKS() {
        return service.getJwk().toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    @PostMapping("/token/validate")
    public ResponseEntity<String> validate(@RequestParam(name = "token", required = true) String token) {
        if (service.validate(token)) {
            return ResponseEntity.ok().body("Token is invalid");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is invalid");
        }
    }

    @GetMapping("/token/generate")
    public ResponseEntity<String> generate() {
        String token = service.generate();
        if (null != token) {
            return ResponseEntity.ok().body(token);
        } else {
            return ResponseEntity.badRequest().body("Cannot generate token");
        }
    }

}

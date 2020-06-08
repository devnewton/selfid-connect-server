package fr.devnewton.selfidconnectserver.controllers;

import fr.devnewton.selfidconnectserver.services.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {

    @Autowired
    private TokenService tokenService;

    @GetMapping("/")
    public String index() {
        return "login-form";
    }

    @PostMapping("/login")
    public String login() {
        String access_token = tokenService.generate();
        return "redirect:/login-successful#access_token=" + access_token;
    }

    @GetMapping("/login-successful")
    public String loginSuccessful() {
        return "login-successful";
    }
}

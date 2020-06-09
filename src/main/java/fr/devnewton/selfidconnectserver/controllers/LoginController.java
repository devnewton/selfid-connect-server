package fr.devnewton.selfidconnectserver.controllers;

import fr.devnewton.selfidconnectserver.services.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class LoginController {

    @Autowired
    private TokenService tokenService;

    @GetMapping("/")
    public String index() {
        return "login-form";
    }

    @GetMapping("/authorize")
    public String authorize(@RequestParam(name = "redirect_uri", required = true) String redirectURI, Model model) {
        model.addAttribute("redirect_uri", redirectURI);
        return "login-form";
    }

    @PostMapping("/login")
    public String login(@RequestParam(name = "redirect_uri", required = false) String redirectURI) {
        UriComponentsBuilder uriBuilder;
        if (StringUtils.hasText(redirectURI)) {
            uriBuilder = UriComponentsBuilder.fromUriString(redirectURI);
        } else {
            uriBuilder = UriComponentsBuilder.fromPath("/login-successful");
        }
        String access_token = tokenService.generate();
        return "redirect:" + uriBuilder.fragment("access_token=" + access_token).toUriString();
    }

    @GetMapping("/login-successful")
    public String loginSuccessful() {
        return "login-successful";
    }
}

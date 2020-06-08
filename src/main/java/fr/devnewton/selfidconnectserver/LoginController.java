package fr.devnewton.selfidconnectserver;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class LoginController {

    @GetMapping("/")
    public String index() {
        return "login-form";
    }
    
    @PostMapping("/login")
    public String login() {
        String access_token = generateToken();
        return "redirect:/login-successful#access_token=" + access_token;
    }
    
    @GetMapping("/login-successful")
    public String loginSuccessful() {
        return "login-successful";
    }

    private String generateToken() {
        return "TODO";
    }
}

package com.rouvsen.springsecurityapp.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/public")
public class PublicController {

    @GetMapping
    public String publicMethod() {
        return "Hello World! from PublicController";
    }
}

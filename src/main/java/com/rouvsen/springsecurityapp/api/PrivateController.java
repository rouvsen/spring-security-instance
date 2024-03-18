package com.rouvsen.springsecurityapp.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/private")
public class PrivateController {

    @GetMapping("/user")
//    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public String privateMethodUser() {
        return "Hello World! from PrivateController > USER";
    }

    @GetMapping("/admin")
//    @PreAuthorize("hasRole('ADMIN')")
    public String privateMethodAdmin() {
        return "Hello World! from PrivateController > ADMIN";
    }
}

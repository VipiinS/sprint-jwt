package com.vipin.JWTdemo.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/useronly")
    @PreAuthorize("hasAnyRole('ROLE_USER')")
    public ResponseEntity<String> userOnly(){
        return ResponseEntity.ok("User only endpoint accesed");
    }
}

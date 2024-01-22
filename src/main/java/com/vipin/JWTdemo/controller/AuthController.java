package com.vipin.JWTdemo.controller;

import com.vipin.JWTdemo.dtos.JwtResponseDTO;
import com.vipin.JWTdemo.dtos.RequestDTO;
import com.vipin.JWTdemo.entity.Role;
import com.vipin.JWTdemo.entity.UserInfo;
import com.vipin.JWTdemo.repository.UserRepository;
import com.vipin.JWTdemo.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {
    @Autowired
    private  JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/open")
    public String unProtected(){
        return "Unprotected endpoint";
    }


    @PostMapping("/signin")
    public ResponseEntity<JwtResponseDTO>  authenticateUser(@RequestBody RequestDTO requestDTO){
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(requestDTO.getUsername(), requestDTO.getPassword()));

        if(authentication.isAuthenticated()){
            // Extract roles from the Authentication object
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();


            // Convert GrantedAuthority objects to role strings
            List<String> roles = authorities.stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());


            JwtResponseDTO responseDTO = new JwtResponseDTO();
            responseDTO.setToken(jwtService.generateToken(requestDTO.getUsername(), roles));
            System.out.println(responseDTO.getToken());
            return ResponseEntity.ok(responseDTO);

        }else {
            throw new UsernameNotFoundException("invalid user request..!!");
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<String> register(@RequestBody RequestDTO requestDTO) {
        // Check if the user already exists
        if (userRepository.existsByUsername(requestDTO.getUsername())) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Username already exists");
        }

        UserInfo user = new UserInfo();
        String encodedPassword = passwordEncoder.encode(requestDTO.getPassword());
        user.setPassword(encodedPassword);
        user.setUsername(requestDTO.getUsername());

        // Convert role names to Role enum instances
        List<Role> userRoles = requestDTO.getRoles().stream()
                .map(Role::valueOf)
                .collect(Collectors.toList());

        user.setRoles(userRoles);

        try {
            userRepository.save(user);
            return ResponseEntity.ok("User registered successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Unable to save in db");
        }
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Admin Endpoint Accessed");
    }

    @GetMapping("/user-or-admin")
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ADMIN')")
    public ResponseEntity<String> userOrAdminEndpoint() {
        return ResponseEntity.ok("User or Admin Endpoint Accessed");
    }
}

package com.example.myapp.controller;

import com.example.myapp.dto.UserResponse;
import com.example.myapp.model.User;
import com.example.myapp.service.AuthenticationService;
import com.example.myapp.service.JwtService;
import com.example.myapp.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@CrossOrigin("*")
@RequestMapping("/auth")
@RestController
public class AuthenticationController {
    private final JwtService jwtService;
    private final UserService userService;
    private final AuthenticationService authenticationService;

    public AuthenticationController(JwtService jwtService, AuthenticationService authenticationService, UserService userService) {
        this.jwtService = jwtService;
        this.authenticationService = authenticationService;
        this.userService = userService;
    }

    @PostMapping("/signup")
    public ResponseEntity<UserResponse> register(@RequestBody User registerUserDto) {
        User registeredUser = authenticationService.signup(registerUserDto);

        UserResponse response = new UserResponse();
        response.setUsername(registeredUser.getUsername());
        response.setEmail(registeredUser.getEmail());
        response.setMessage("User registered successfully");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<UserResponse> authenticate(@RequestBody User loginUserDto) {
        User authenticatedUser = authenticationService.authenticate(loginUserDto);

        String jwtToken = jwtService.generateToken(authenticatedUser);

        UserResponse response = new UserResponse();
        response.setUsername(authenticatedUser.getUsername());
        response.setId(authenticatedUser.getId());
        response.setEmail(authenticatedUser.getEmail());
        response.setToken(jwtToken);
        response.setExpiresIn(jwtService.getExpirationTime());

        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@RequestBody Map<String, String> resetRequest) {
        String email = resetRequest.get("email");
        String newPassword = resetRequest.get("newPassword");

        if (email == null || newPassword == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email or newPassword is missing"));
        }

        boolean resetSuccessful = userService.resetPassword(email, newPassword);
        if (resetSuccessful) {
            return ResponseEntity.ok().body(Map.of("message", "Password Reset Successfully"));
        }

        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "User not found"));
    }
}
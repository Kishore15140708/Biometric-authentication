# Biometric-authentication
package com.example.biometricauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.List;

@RestController
// Allow all origins during development to avoid CORS 'Failed to fetch' errors from the frontend.
@CrossOrigin(origins = "*")
public class BiometricController {
    private final FaceService faceService;
    private final UserRepository userRepository;
    public BiometricController(FaceService faceService, UserRepository userRepository) {
        this.faceService = faceService;
        this.userRepository = userRepository;
    }
    private final Map<String, String> tokens = new HashMap<>(); // In-memory token store
    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody BiometricRequest request) {
        System.out.println("Register request received for userId: " + request.getUserId());
        try {
            if (request.getBiometricImages() == null || request.getBiometricImages().isEmpty()) {
                Map<String, String> error = new HashMap<>();
                error.put("error", "At least 5 face images are required for registration");
                return ResponseEntity.badRequest().body(error);
            }
            faceService.registerUser(request.getUserId(), request.getName(), request.getBiometricImages());
            Map<String, String> response = new HashMap<>();
            response.put("message", "User registered successfully");
            System.out.println("User registered successfully: " + request.getUserId());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.out.println("Failed to register user: " + e.getMessage());
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to register user: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }
    @PostMapping("/verify")
    public ResponseEntity<Map<String, String>> verify(@RequestBody Map<String, String> request) {
        System.out.println("Verify request received");
        String biometricData = request.get("biometricData");
        System.out.println("Biometric data length: " + (biometricData != null ? biometricData.length() : "null"));
        String userId = faceService.verifyUser(biometricData);
        System.out.println("Verification result: " + userId);
        if (userId != null) {
            String token = UUID.randomUUID().toString();
            tokens.put(token, userId);
            Map<String, String> response = new HashMap<>();
            response.put("userId", userId);
            response.put("token", token);
            System.out.println("Authentication successful for user: " + userId);
            return ResponseEntity.ok(response);
        } else {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication failed");
            System.out.println("Authentication failed");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }
    @PostMapping("/verify-realtime")
    public ResponseEntity<Map<String, String>> verifyRealtime(@RequestBody Map<String, String> request) {
        System.out.println("Real-time verify request received");
        String biometricData = request.get("biometricData");
        String userId = faceService.verifyUser(biometricData);
        System.out.println("Real-time verification result: " + userId);
        Map<String, String> response = new HashMap<>();
        if (userId != null) {
            String token = UUID.randomUUID().toString();
            tokens.put(token, userId);
            response.put("success", "true");
            response.put("userId", userId);
            response.put("token", token);
            System.out.println("Real-time authentication successful for user: " + userId);
        } else {
            response.put("success", "false");
            System.out.println("Real-time authentication failed");
        }
        return ResponseEntity.ok(response);
    }
    @GetMapping("/file")
    public ResponseEntity<String> getFile(@RequestParam String token) {
        String userId = tokens.get(token);
        if (userId != null) {
            try {
                Path filePath = Paths.get("src/main/resources/static/secure-data.txt");
                String content = Files.readString(filePath);
                return ResponseEntity.ok(content);
            } catch (IOException e) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error reading file");
            }
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Invalid token");
        }
    }
    // Development utility: list all registered user IDs (no sensitive data)
    @GetMapping("/users")
    public ResponseEntity<?> listUsers() {
        try {
            List<User> users = userRepository.findAll();
            List<String> ids = new java.util.ArrayList<>();
            for (User u : users) {
                ids.add(u.getUserId());
            }
            return ResponseEntity.ok(ids);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error fetching users: " + e.getMessage());
        }
    }
    // Simple health check endpoint
    @GetMapping("/ping")
    public ResponseEntity<String> ping() {
        return ResponseEntity.ok("pong");
    }
}

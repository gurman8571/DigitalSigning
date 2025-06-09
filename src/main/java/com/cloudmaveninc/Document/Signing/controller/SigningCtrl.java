package com.cloudmaveninc.Document.Signing.controller;

import com.cloudmaveninc.Document.Signing.service.AzureSigner;
import org.springframework.stereotype.Controller;
import com.cloudmaveninc.Document.Signing.dto.SignRequest;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
@CrossOrigin(origins = "*")
@Controller
@RequestMapping("/api")
public class SigningCtrl {
    private final AzureSigner signerService;

     // constructor
    public SigningCtrl(AzureSigner signerService) {
        this.signerService = signerService;
    }

    @PostMapping("/sign")
    public ResponseEntity<?> signPdf(@RequestBody SignRequest request) {
        try {
            String base64 = request.getBase64Content();
            //String base64 = request.get("base64Content");
            byte[] pkcs7 = signerService.signWithAzure(base64);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, "application/octet-stream")
                    .body(pkcs7);

        } catch (Exception e) {
            Map<String,String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Failed to sign PDF");
            errorResponse.put("details", e.getMessage()); // you can customize this if you don't want to expose all error details
            return ResponseEntity.status(500).body(errorResponse);
        }
    }

    @GetMapping("/test")
    public String Message(){
        return "Server up and running";
    }
}

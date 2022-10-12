package com.evanjon.studySpringJwt.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.evanjon.studySpringJwt.security.utils.JwtTokenUtil;

@RestController
public class JwtAuthenticationController {
    
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationController.class);
    
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    
    @GetMapping("/authenticate")
    public String createAuthenticationToken(String username, String password) {
        logger.debug("In " + this.getClass().getName() + "::createAuthenticationToken");
        
        final String token = jwtTokenUtil.generateToken(username);
        
        return token;
    }
}

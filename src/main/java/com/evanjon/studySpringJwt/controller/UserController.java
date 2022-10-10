package com.evanjon.studySpringJwt.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private static final Logger logger = LoggerFactory.getLogger(UserController.class);
    
    @GetMapping("/user")
    public String user() {
        logger.debug("In " + this.getClass().getName() + "::user()");
        
        return "user";
    }
}

package com.org.SecurityJWT.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestRolesController {
    @GetMapping("/AccessAdmin")
    @PreAuthorize("Hasrole('ADMIN')")
    public String accessAdmin (){
        return "Hey, has accedido con el rol de ADMIN ";
    }
    @GetMapping("/AccessUser")
    @PreAuthorize("Hasrole('USER')")
    public String accessUser(){
        return "Hey, has accedido con el rol de USER ";
    }
    @GetMapping("/AccessInvited")
    @PreAuthorize("Hasrole('INVITED')")
    public String accessInvited(){
        return "Hey, has accedido con el rol de INVITED";
    }
}

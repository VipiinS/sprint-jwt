package com.vipin.JWTdemo.dtos;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class RequestDTO { //signup
    private String username;
    private String password;
    private List<String> roles;

}

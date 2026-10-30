package com.example.app;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {
    private final Handler handler = new Handler();

    @PostMapping("/parse")
    public Object parse(@RequestBody String body) {
        return handler.handle(body);
    }
}

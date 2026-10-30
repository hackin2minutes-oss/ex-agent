package com.example.app;

import com.example.Parser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Positive control: remote input reaches Parser.parse with no intermediate call.
// The taint stage must report this flow. If it does not, the taint query is broken.
@RestController
public class DirectController {
    @GetMapping("/direct")
    public Object direct(@RequestParam String q) {
        return Parser.parse(q);
    }
}

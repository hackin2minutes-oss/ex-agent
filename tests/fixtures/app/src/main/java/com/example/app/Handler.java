package com.example.app;

import com.example.Parser;

public class Handler {
    public Object handle(String input) {
        return Parser.parse(input);
    }
}

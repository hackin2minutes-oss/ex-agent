package com.example;

// Stand-in for the vulnerable library's method, so CodeQL can resolve the call target.
public class Parser {
    public static Object parse(String input) {
        return input;
    }
}

package io.github.chains_project.theo.package_static_analyzer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.*;

class FormatNameTest {

    @ParameterizedTest(name = "\"{0}\" -> \"{1}\"")
    @CsvSource({
            // $ followed by a letter becomes a dot (inner class separator)
            "com.example.Outer$Inner,         com.example.Outer.Inner",
            "com.example.Outer$Inner$Deep,     com.example.Outer.Inner.Deep",

            // $ followed by a digit is removed (anonymous class)
            "com.example.Foo$1,               com.example.Foo",
            "com.example.Foo$123,             com.example.Foo",

            // Mixed: inner class + anonymous
            "com.example.Outer$Inner$1,       com.example.Outer.Inner",

            // No $ at all — unchanged
            "com.example.NormalClass,         com.example.NormalClass",
            "getValue,                         getValue",

            // Constructor
            "<init>,                           <init>",
    })
    void formatsNamesCorrectly(String input, String expected) {
        assertEquals(expected.trim(), PackageStaticAnalyzer.formatName(input.trim()));
    }

    @Test
    void formatNameHandlesConsecutiveDollarDigits() {
        // e.g. Foo$1$2 — both anonymous markers removed
        assertEquals("com.example.Foo", PackageStaticAnalyzer.formatName("com.example.Foo$1$2"));
    }

    @Test
    void formatNameHandlesDollarLetterThenDigit() {
        // Outer$Inner$1 — Inner becomes dot, $1 is removed
        assertEquals("com.Outer.Inner", PackageStaticAnalyzer.formatName("com.Outer$Inner$1"));
    }
}

package com.cynera.backend.detection.ransomware;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EntropyCalculatorTest {

    private final EntropyCalculator calculator = new EntropyCalculator();

    @Test
    void shouldReturnZeroForNullData() {
        assertEquals(0.0, calculator.calculate((byte[]) null));
        assertEquals(0.0, calculator.calculate((String) null));
    }

    @Test
    void shouldReturnZeroForEmptyData() {
        assertEquals(0.0, calculator.calculate(new byte[0]));
        assertEquals(0.0, calculator.calculate(""));
    }

    @Test
    void shouldReturnZeroForUniformData() {
        byte[] data = new byte[100];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) 0x41;
        }
        assertEquals(0.0, calculator.calculate(data), 0.0001);
    }

    @Test
    void shouldReturnMaxEntropyForUniformDistribution() {
        byte[] data = new byte[256];
        for (int i = 0; i < 256; i++) {
            data[i] = (byte) i;
        }
        double entropy = calculator.calculate(data);
        assertEquals(8.0, entropy, 0.01);
    }

    @Test
    void shouldReturnHighEntropyForRandomData() {
        byte[] data = new byte[1000];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (i % 256);
        }
        double entropy = calculator.calculate(data);
        assertTrue(entropy > 7.5);
    }

    @Test
    void shouldReturnLowEntropyForTextData() {
        String text = "This is a normal text file with readable content.";
        double entropy = calculator.calculate(text);
        assertTrue(entropy < 5.0);
    }

    @Test
    void shouldReturnHighEntropyForEncryptedData() {
        byte[] encrypted = new byte[1000];
        for (int i = 0; i < encrypted.length; i++) {
            encrypted[i] = (byte) (Math.random() * 256);
        }
        double entropy = calculator.calculate(encrypted);
        assertTrue(entropy > 7.5);
    }

    @Test
    void shouldDetectHighEntropyWithThreshold() {
        byte[] highEntropyData = new byte[256];
        for (int i = 0; i < 256; i++) {
            highEntropyData[i] = (byte) i;
        }

        assertTrue(calculator.isHighEntropy(highEntropyData, 7.0));
        assertFalse(calculator.isHighEntropy(highEntropyData, 8.5));
    }

    @Test
    void shouldReturnMaxEntropyConstant() {
        assertEquals(8.0, EntropyCalculator.getMaxEntropy(), 0.0001);
    }
}
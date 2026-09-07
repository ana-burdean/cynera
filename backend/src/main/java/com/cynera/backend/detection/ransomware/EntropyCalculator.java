package com.cynera.backend.detection.ransomware;

import org.springframework.stereotype.Component;

@Component
public class EntropyCalculator {

    private static final int BYTE_RANGE = 256;

    public double calculate(byte[] data) {
        if (data == null || data.length == 0) {
            return 0.0;
        }

        int[] frequencies = new int[BYTE_RANGE];
        for (byte b : data) {
            frequencies[b & 0xFF]++;
        }

        double entropy = 0.0;
        int dataLength = data.length;

        for (int freq : frequencies) {
            if (freq > 0) {
                double probability = (double) freq / dataLength;
                entropy -= probability * (Math.log(probability) / Math.log(2));
            }
        }

        return entropy;
    }

    public double calculate(String data) {
        if (data == null || data.isEmpty()) {
            return 0.0;
        }
        return calculate(data.getBytes());
    }

    public boolean isHighEntropy(byte[] data, double threshold) {
        return calculate(data) >= threshold;
    }

    public boolean isHighEntropy(String data, double threshold) {
        return calculate(data) >= threshold;
    }

    public static double getMaxEntropy() {
        return Math.log(BYTE_RANGE) / Math.log(2);
    }
}
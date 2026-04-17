package io.github.abdallah.secretscanner.engine;

public final class Entropy {

    private Entropy() {}

    /** Shannon entropy (base-2) of the string's characters. */
    public static double of(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        int[] freq = new int[256];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 256) freq[c]++;
        }
        double len = s.length();
        double entropy = 0.0;
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }
}

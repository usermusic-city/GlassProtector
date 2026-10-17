package com.luoye.dpt.dex;

import java.security.SecureRandom;

/**
 * Build-time XOR cipher for helper method strings.
 */
public final class StringXorCipher {

    private static final SecureRandom RANDOM = new SecureRandom();

    private StringXorCipher() {
    }

    public static int randomKey() {
        return RANDOM.nextInt(255) + 1;
    }

    public static String encrypt(String plain, int key) {
        char[] chars = plain.toCharArray();
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (chars[i] ^ key);
        }
        return new String(chars);
    }
}
